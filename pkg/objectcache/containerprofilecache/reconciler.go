// Package containerprofilecache — reconciler.go
//
// The reconciler is the safety-net eviction path AND the freshness refresh
// loop. Each tick it:
//   1. reconcileOnce: evicts cache entries whose pod is gone or whose
//      container is no longer Running.
//   2. refreshAllEntries (single-flight via atomic flag): re-fetches CP + any
//      user-authored AP/NN overlay and rebuilds the projection iff any
//      resourceVersion changed. Fast-skip when CP + userAP + userNN RVs all
//      match what's already cached.
//
// RPC cost @ 300 containers / 30s cadence: ≤10 RPC/s steady-state (CP Get
// only); ≤20 RPC/s when every entry has both user-AP + user-NN overlay (worst
// case: 3 gets × 300 entries / 30s = 30 RPC/s). Overlay load is typically a
// small fraction of pods in production deployments. (delta #7)
package containerprofilecache

import (
	"context"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/callstackcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

// tickLoop drives the reconciler. Evict runs synchronously on the tick;
// refresh runs on a single-flight goroutine guarded by refreshInProgress so a
// slow refresh never stacks.
func (c *ContainerProfileCacheImpl) tickLoop(ctx context.Context) {
	if c.reconcileEvery == 0 {
		c.reconcileEvery = defaultReconcileInterval
	}
	ticker := time.NewTicker(c.reconcileEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.L().Info("ContainerProfileCache reconciler stopped")
			return
		case <-ticker.C:
			start := time.Now()
			c.reconcileOnce(ctx)
			c.metricsManager.ReportContainerProfileReconcilerDuration(time.Since(start))
			if c.refreshInProgress.CompareAndSwap(false, true) {
				go func() {
					defer c.refreshInProgress.Store(false)
					c.refreshAllEntries(ctx)
				}()
			}
		}
	}
}

// reconcileOnce evicts cache entries whose container is no longer Running.
// Exposed (lowercase but package-public) for tests.
func (c *ContainerProfileCacheImpl) reconcileOnce(ctx context.Context) {
	var toEvict []string
	c.entries.Range(func(id string, e *CachedContainerProfile) bool {
		if ctx.Err() != nil { // delta #3: honor cancellation mid-range
			return false
		}
		pod := c.k8sObjectCache.GetPod(e.Namespace, e.PodName)
		if pod == nil {
			toEvict = append(toEvict, id)
			return true
		}
		if !isContainerRunning(pod, e, id) { // delta #1: three-arg signature
			toEvict = append(toEvict, id)
		}
		return true
	})
	for _, id := range toEvict {
		c.containerLocks.WithLock(id, func() {
			c.entries.Delete(id)
		})
		// See deleteContainer comment on why we don't ReleaseLock here.
		c.metricsManager.ReportContainerProfileReconcilerEviction("pod_stopped")
	}
	c.metricsManager.SetContainerProfileCacheEntries("total", float64(c.entries.Len()))
}

// isContainerRunning reports whether the container identified by `id` (the
// cache key, a trimmed containerID) or by (e.ContainerName, e.PodUID) is in
// State=Running in the pod's container/initContainer/ephemeralContainer
// statuses.
//
// Pre-running init containers can appear with an empty ContainerID in the
// status (kubelet hasn't published it yet). In that case we fall back to
// matching on (Name, PodUID) so we don't prematurely evict the entry the
// instant it's populated.
func isContainerRunning(pod *corev1.Pod, e *CachedContainerProfile, id string) bool {
	statuses := make([]corev1.ContainerStatus, 0,
		len(pod.Status.ContainerStatuses)+
			len(pod.Status.InitContainerStatuses)+
			len(pod.Status.EphemeralContainerStatuses))
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	statuses = append(statuses, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)
	for _, s := range statuses {
		if s.ContainerID == "" {
			// pre-running init container: match by (Name, PodUID)
			if s.Name == e.ContainerName && string(pod.UID) == e.PodUID {
				return s.State.Running != nil
			}
			continue
		}
		if utils.TrimRuntimePrefix(s.ContainerID) == id {
			return s.State.Running != nil
		}
	}
	return false
}

// refreshAllEntries re-fetches CP + user AP/NN for each cache entry and
// updates the projection if any ResourceVersion changed. Fast-skip when RV +
// UserAPRV + UserNNRV all match (delta #4). Exposed for tests.
func (c *ContainerProfileCacheImpl) refreshAllEntries(ctx context.Context) {
	start := time.Now()
	defer func() {
		c.metricsManager.ReportContainerProfileReconcilerDuration(time.Since(start))
	}()
	// Snapshot first to avoid holding SafeMap's RLock while refreshOneEntry
	// writes back via Set (which needs the write lock).
	type snapshot struct {
		id string
		e  *CachedContainerProfile
	}
	var work []snapshot
	c.entries.Range(func(id string, e *CachedContainerProfile) bool {
		if ctx.Err() != nil { // delta #3
			return false
		}
		work = append(work, snapshot{id: id, e: e})
		return true
	})
	for _, w := range work {
		if ctx.Err() != nil {
			return
		}
		c.containerLocks.WithLock(w.id, func() {
			c.refreshOneEntry(ctx, w.id, w.e)
		})
	}
}

// refreshOneEntry refreshes a single cache entry under the per-container lock.
// On any non-fatal error (CP fetch failure) we keep the existing entry — the
// next tick will retry.
func (c *ContainerProfileCacheImpl) refreshOneEntry(_ context.Context, id string, e *CachedContainerProfile) {
	cp, err := c.storageClient.GetContainerProfile(e.Namespace, e.CPName)
	if err != nil {
		logger.L().Debug("refreshOneEntry: failed to re-fetch CP; keeping cached entry",
			helpers.String("containerID", id),
			helpers.String("cpName", e.CPName),
			helpers.Error(err))
		return
	}
	if cp == nil {
		logger.L().Debug("refreshOneEntry: CP missing from storage; keeping cached entry",
			helpers.String("containerID", id),
			helpers.String("cpName", e.CPName))
		return
	}

	// Fast-skip (delta #4): if CP RV unchanged AND neither overlay present,
	// no work to do. With overlays present, also confirm their RVs before
	// skipping.
	if cp.ResourceVersion == e.RV {
		if e.UserAPRef == nil && e.UserNNRef == nil {
			return
		}
		var apRV, nnRV string
		var userAP *v1beta1.ApplicationProfile
		var userNN *v1beta1.NetworkNeighborhood
		if e.UserAPRef != nil {
			if ap, aerr := c.storageClient.GetApplicationProfile(e.UserAPRef.Namespace, e.UserAPRef.Name); aerr == nil && ap != nil {
				apRV = ap.ResourceVersion
				userAP = ap
			}
		}
		if e.UserNNRef != nil {
			if nn, nerr := c.storageClient.GetNetworkNeighborhood(e.UserNNRef.Namespace, e.UserNNRef.Name); nerr == nil && nn != nil {
				nnRV = nn.ResourceVersion
				userNN = nn
			}
		}
		if apRV == e.UserAPRV && nnRV == e.UserNNRV {
			return
		}
		// Something in the overlay changed — rebuild using the fetches we
		// already have to avoid a second RPC round-trip.
		c.rebuildEntry(id, e, cp, userAP, userNN)
		return
	}

	// Base CP changed — rebuild with fresh overlay fetches too.
	var userAP *v1beta1.ApplicationProfile
	var userNN *v1beta1.NetworkNeighborhood
	if e.UserAPRef != nil {
		if ap, aerr := c.storageClient.GetApplicationProfile(e.UserAPRef.Namespace, e.UserAPRef.Name); aerr == nil {
			userAP = ap
		}
	}
	if e.UserNNRef != nil {
		if nn, nerr := c.storageClient.GetNetworkNeighborhood(e.UserNNRef.Namespace, e.UserNNRef.Name); nerr == nil {
			userNN = nn
		}
	}
	c.rebuildEntry(id, e, cp, userAP, userNN)
}

// rebuildEntry constructs a fresh CachedContainerProfile from the given
// inputs and stores it under `id`. Called by the reconciler when any input
// ResourceVersion has changed.
func (c *ContainerProfileCacheImpl) rebuildEntry(
	id string,
	prev *CachedContainerProfile,
	cp *v1beta1.ContainerProfile,
	userAP *v1beta1.ApplicationProfile,
	userNN *v1beta1.NetworkNeighborhood,
) {
	pod := c.k8sObjectCache.GetPod(prev.Namespace, prev.PodName)

	shared := userAP == nil && userNN == nil
	var projected *v1beta1.ContainerProfile
	var warnings []partialProfileWarning
	if shared {
		projected = cp
	} else {
		projected, warnings = projectUserProfiles(cp, userAP, userNN, pod, prev.ContainerName)
	}

	c.emitOverlayMetrics(userAP, userNN, warnings)

	// Rebuild the call-stack search tree from the projected profile.
	tree := callstackcache.NewCallStackSearchTree()
	for _, stack := range projected.Spec.IdentifiedCallStacks {
		tree.AddCallStack(stack)
	}

	newEntry := &CachedContainerProfile{
		Profile:       projected,
		State:         &objectcache.ProfileState{Completion: cp.Annotations[helpersv1.CompletionMetadataKey], Status: cp.Annotations[helpersv1.StatusMetadataKey], Name: cp.Name},
		CallStackTree: tree,
		ContainerName: prev.ContainerName,
		PodName:       prev.PodName,
		Namespace:     prev.Namespace,
		PodUID:        prev.PodUID,
		WorkloadID:    prev.WorkloadID,
		CPName:        cp.Name,
		Shared:        shared,
		RV:            cp.ResourceVersion,
		UserAPRV:      rvOrEmpty(userAP),
		UserNNRV:      rvOrEmpty(userNN),
	}
	if userAP != nil {
		newEntry.UserAPRef = &namespacedName{Namespace: userAP.Namespace, Name: userAP.Name}
	} else if prev.UserAPRef != nil {
		// Preserve the ref so subsequent ticks still know to re-fetch the
		// overlay (e.g. transient fetch error during this tick).
		newEntry.UserAPRef = prev.UserAPRef
	}
	if userNN != nil {
		newEntry.UserNNRef = &namespacedName{Namespace: userNN.Namespace, Name: userNN.Name}
	} else if prev.UserNNRef != nil {
		newEntry.UserNNRef = prev.UserNNRef
	}

	c.entries.Set(id, newEntry)
}

// rvOrEmpty returns the object's ResourceVersion, or "" if the object is nil.
// Used by refresh to record the RVs tied to the newly-built projection.
func rvOrEmpty(obj interface {
	GetResourceVersion() string
}) string {
	// Typed-nil guard: callers pass concrete pointer types that may be nil;
	// Go's nil-interface trap means a nil *v1beta1.ApplicationProfile wrapped
	// in the metav1.Object interface is not == nil. Check via reflection-lite:
	if obj == nil {
		return ""
	}
	// The concrete types here are *v1beta1.ApplicationProfile and
	// *v1beta1.NetworkNeighborhood. Both return "" from GetResourceVersion
	// when their ObjectMeta is zero, but we want to return "" for a nil
	// pointer specifically. Narrow the check:
	switch v := obj.(type) {
	case *v1beta1.ApplicationProfile:
		if v == nil {
			return ""
		}
		return v.ResourceVersion
	case *v1beta1.NetworkNeighborhood:
		if v == nil {
			return ""
		}
		return v.ResourceVersion
	}
	return obj.GetResourceVersion()
}
