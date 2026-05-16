// Package containerprofilecache — reconciler.go
//
// The reconciler is the safety-net eviction path AND the freshness refresh
// loop. Each tick it:
//   1. reconcileOnce: evicts cache entries whose pod is gone or whose
//      container is no longer Running.
//   2. refreshAllEntries (single-flight via atomic flag): re-fetches the
//      consolidated CP, the workload-level AP+NN, the user-managed
//      "ug-<workload>" AP+NN, and any label-referenced user AP/NN overlay,
//      then rebuilds the projection iff any resourceVersion changed. Fast-skip
//      when every RV matches what's already cached.
//
// RPC cost @ 300 containers / 30s cadence steady-state: up to 7 gets per
// entry per tick (CP + 3×AP + 3×NN). At 300 entries that's 70 RPC/s in the
// worst case, dropping close to 0 once fast-skip catches on. Most entries
// carry only workload-level AP+NN, so the common case is 3 RPC/tick per
// entry = 30 RPC/s.
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// tickLoop drives the reconciler. Evict runs synchronously on the tick;
// refresh runs on a single-flight goroutine guarded by refreshInProgress so a
// slow refresh never stacks.
func (c *ContainerProfileCacheImpl) tickLoop(ctx context.Context) {
	if c.reconcileEvery == 0 {
		c.reconcileEvery = defaultReconcileInterval
	}
	logger.L().Info("ContainerProfileCache reconciler started",
		helpers.String("interval", c.reconcileEvery.String()))
	ticker := time.NewTicker(c.reconcileEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.L().Info("ContainerProfileCache reconciler stopped")
			return
		case <-c.nudge:
			// Spec changed — re-project all entries immediately without
			// waiting for the next periodic tick. Use trailing-edge consolidation:
			// mark pending so that if a refresh is already running it will
			// re-run once after it finishes, preventing entries from staying on
			// an old spec for up to one full reconcile interval.
			if c.cfg.ProfileProjection.DetailedMetricsEnabled {
				c.metricsManager.IncProjectionReconcileTriggered("nudge")
			}
			c.refreshPending.Store(true)
			if c.refreshInProgress.CompareAndSwap(false, true) {
				go func() {
					defer c.refreshInProgress.Store(false)
					for c.refreshPending.Swap(false) {
						c.refreshAllEntries(ctx)
					}
				}()
			}
		case <-ticker.C:
			if c.cfg.ProfileProjection.DetailedMetricsEnabled {
				c.metricsManager.IncProjectionReconcileTriggered("tick")
			}
			start := time.Now()
			entriesBefore := c.entries.Len()
			pendingBefore := c.pending.Len()
			c.reconcileOnce(ctx)
			c.retryPendingEntries(ctx)
			// Emit the debug breadcrumb only when something actually moved:
			// entries delta != 0 OR pending delta != 0. Keeping the log gated
			// avoids flooding the journal with identical zero-delta ticks while
			// still leaving the observability hook for the test-regression
			// investigations that motivated the log.
			entriesAfter := c.entries.Len()
			pendingAfter := c.pending.Len()
			if entriesBefore != entriesAfter || pendingBefore != pendingAfter {
				logger.L().Debug("ContainerProfileCache reconciler tick",
					helpers.Int("entries_before", entriesBefore),
					helpers.Int("entries_after", entriesAfter),
					helpers.Int("pending_before", pendingBefore),
					helpers.Int("pending_after", pendingAfter))
			}
			c.metricsManager.ReportContainerProfileReconcilerDuration("evict", time.Since(start))
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
			// Pod not yet in k8s cache (or briefly absent during watch
			// resync). Do NOT evict — the pod cache routinely lags the
			// ContainerCallback Add events by tens of seconds on busy nodes,
			// and evicting here would churn every entry every tick until the
			// cache catches up. Cleanup for terminated containers flows
			// through deleteContainer on EventTypeRemoveContainer.
			return true
		}
		// Only evict when the pod IS in cache AND the container has clearly
		// exited (Terminated state). "Not yet Running" (Waiting state) is
		// NOT a reason to evict — init containers and pre-running containers
		// legitimately pass through Waiting before transitioning to Running.
		if isContainerTerminated(pod, e, id) {
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

	// NOTE: we intentionally do NOT GC pending entries based on pod state.
	// A previous version dropped pending entries when GetPod returned nil or
	// the container wasn't yet Running — but the k8s pod cache and container
	// statuses lag the containerwatcher Add event by tens of seconds on busy
	// nodes, so the GC dropped every pending entry before retries had a
	// chance to succeed. Cleanup for terminated containers flows through
	// deleteContainer (EventTypeRemoveContainer) which clears both entries
	// and pending atomically. Memory growth from stuck-pending entries is
	// bounded by the node's container churn.

	c.metricsManager.SetContainerProfileCacheEntries("total", float64(c.entries.Len()))
	c.metricsManager.SetContainerProfileCacheEntries("pending", float64(c.pending.Len()))
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
// isContainerTerminated reports whether the container identified by `id` or
// by (e.ContainerName, e.PodUID) has a Terminated state in the pod's
// container/initContainer/ephemeralContainer statuses. This is stricter than
// "not Running": a container in Waiting state is NOT considered terminated.
// Used by reconcileOnce as the eviction signal.
func isContainerTerminated(pod *corev1.Pod, e *CachedContainerProfile, id string) bool {
	statuses := make([]corev1.ContainerStatus, 0,
		len(pod.Status.ContainerStatuses)+
			len(pod.Status.InitContainerStatuses)+
			len(pod.Status.EphemeralContainerStatuses))
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	statuses = append(statuses, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.EphemeralContainerStatuses...)
	for _, s := range statuses {
		if s.ContainerID == "" {
			if s.Name == e.ContainerName && string(pod.UID) == e.PodUID {
				return s.State.Terminated != nil
			}
			continue
		}
		if utils.TrimRuntimePrefix(s.ContainerID) == id {
			return s.State.Terminated != nil
		}
	}
	// Container not found in any status list. If no statuses have been
	// published yet (kubelet lag on a brand-new pod), do NOT evict — the
	// empty list is indistinguishable from a fully-reaped container otherwise.
	if len(statuses) == 0 {
		return false
	}
	// Statuses were published but this container is absent: it was reaped.
	return true
}

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
		c.metricsManager.ReportContainerProfileReconcilerDuration("refresh", time.Since(start))
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

	c.currentSpecMu.RLock()
	var currentHash string
	if c.currentSpec != nil {
		currentHash = c.currentSpec.Hash
	}
	c.currentSpecMu.RUnlock()
	var stale float64
	c.entries.Range(func(_ string, e *CachedContainerProfile) bool {
		if e.SpecHash != currentHash {
			stale++
		}
		return true
	})
	c.metricsManager.SetProjectionStaleEntries(stale)
}

// refreshOneEntry refreshes a single cache entry under the per-container lock.
// Re-fetches ALL sources the entry was originally built from (consolidated CP,
// workload-level AP/NN, user-managed AP/NN at "ug-<workloadName>", and any
// label-referenced user AP/NN overlay) and rebuilds the projection if ANY
// ResourceVersion changed. Keeping the existing entry on fetch errors is fine:
// the next tick will retry.
//
// Rebuild on refresh applies the same projection ladder as tryPopulateEntry:
//
//	base CP → workload AP+NN → user-managed (ug-) AP+NN → user overlay AP+NN.
//
// We intentionally DO NOT re-apply the partial-on-non-PreRunning gate here:
// any entry that survived addContainer already passed that gate (or was
// PreRunning), so refresh can accept partial profiles freely. (Fix B for
// Test_17 / Test_19: the workload AP/NN must be re-fetched each tick so a
// "ready" -> "completed" transition propagates to ProfileState.Status, which
// in turn promotes fail_on_profile from false to true.)
func (c *ContainerProfileCacheImpl) refreshOneEntry(ctx context.Context, id string, e *CachedContainerProfile) {
	// Resurrection guard (reviewer #1): refreshAllEntries snapshots entries
	// without holding containerLocks, so a concurrent deleteContainer /
	// reconcile-evict may have removed the entry between snapshot and lock
	// acquisition. If so, bail; otherwise the rebuild's c.entries.Set would
	// resurrect a dead container.
	if _, still := c.entries.Load(id); !still {
		return
	}

	ns := e.Namespace

	// Re-fetch all sources. CP fetch errors (including 404) are treated as
	// "not available right now" — mirroring tryPopulateEntry's behavior. We
	// leave cp=nil and rely on the RV-match fast-skip below to preserve the
	// existing entry when nothing has changed. This is what lets refresh
	// pick up workload-level AP/NN transitions ("ready" -> "completed") even
	// while the storage-side consolidated CP remains unpublished.
	var cp *v1beta1.ContainerProfile
	var cpErr error
	_ = c.refreshRPC(ctx, func(rctx context.Context) error {
		cp, cpErr = c.storageClient.GetContainerProfile(rctx, ns, e.CPName)
		return cpErr
	})
	if cpErr != nil {
		// If the previous entry was built off a real CP (non-empty RV), a
		// CP fetch error on this tick is transient — keep the entry as-is.
		// If the entry never had a CP (RV == "", pure workload/user-managed
		// build), treat the error as 404 and let workload/user-managed
		// re-fetches drive any refresh.
		if e.RV != "" {
			logger.L().Debug("refreshOneEntry: CP fetch failed; keeping cached entry",
				helpers.String("containerID", id),
				helpers.String("cpName", e.CPName),
				helpers.Error(cpErr))
			return
		}
		logger.L().Debug("refreshOneEntry: CP fetch failed (no prior CP); treating as not-available",
			helpers.String("containerID", id),
			helpers.String("cpName", e.CPName),
			helpers.Error(cpErr))
		cp = nil
	}
	var userManagedAP *v1beta1.ApplicationProfile
	var userManagedNN *v1beta1.NetworkNeighborhood
	if e.WorkloadName != "" {
		ugAPName := helpersv1.UserApplicationProfilePrefix + e.WorkloadName
		var userManagedAPErr error
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			userManagedAP, userManagedAPErr = c.storageClient.GetApplicationProfile(rctx, ns, ugAPName)
			return userManagedAPErr
		})
		if userManagedAPErr != nil && e.UserManagedAPRV != "" {
			logger.L().Debug("refreshOneEntry: user-managed AP fetch failed; keeping cached entry",
				helpers.String("containerID", id),
				helpers.String("name", ugAPName),
				helpers.Error(userManagedAPErr))
			return
		}
		if userManagedAPErr != nil {
			userManagedAP = nil // k8s client returns non-nil zero-value on 404; treat as absent
		}
		ugNNName := helpersv1.UserNetworkNeighborhoodPrefix + e.WorkloadName
		var userManagedNNErr error
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			userManagedNN, userManagedNNErr = c.storageClient.GetNetworkNeighborhood(rctx, ns, ugNNName)
			return userManagedNNErr
		})
		if userManagedNNErr != nil && e.UserManagedNNRV != "" {
			logger.L().Debug("refreshOneEntry: user-managed NN fetch failed; keeping cached entry",
				helpers.String("containerID", id),
				helpers.String("name", ugNNName),
				helpers.Error(userManagedNNErr))
			return
		}
		if userManagedNNErr != nil {
			userManagedNN = nil
		}
	}
	var userAP *v1beta1.ApplicationProfile
	var userNN *v1beta1.NetworkNeighborhood
	if e.UserAPRef != nil {
		var userAPErr error
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			userAP, userAPErr = c.storageClient.GetApplicationProfile(rctx, e.UserAPRef.Namespace, e.UserAPRef.Name)
			return userAPErr
		})
		if userAPErr != nil && e.UserAPRV != "" {
			logger.L().Debug("refreshOneEntry: user-defined AP fetch failed; keeping cached entry",
				helpers.String("containerID", id),
				helpers.String("name", e.UserAPRef.Name),
				helpers.Error(userAPErr))
			return
		}
		if userAPErr != nil {
			userAP = nil
		}
	}
	if e.UserNNRef != nil {
		var userNNErr error
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			userNN, userNNErr = c.storageClient.GetNetworkNeighborhood(rctx, e.UserNNRef.Namespace, e.UserNNRef.Name)
			return userNNErr
		})
		if userNNErr != nil && e.UserNNRV != "" {
			logger.L().Debug("refreshOneEntry: user-defined NN fetch failed; keeping cached entry",
				helpers.String("containerID", id),
				helpers.String("name", e.UserNNRef.Name),
				helpers.Error(userNNErr))
			return
		}
		if userNNErr != nil {
			userNN = nil
		}
	}

	// Fast-skip when nothing changed. We match "absent" (nil) with empty RV:
	// this avoids spurious rebuilds when an optional source is still missing,
	// as long as it was also missing at the last build. Also skip when the
	// projection spec hash matches: if neither the data nor the spec changed,
	// the projected output would be identical.
	currentSpecHash := ""
	if spec := c.snapshotSpec(); spec != nil {
		currentSpecHash = spec.Hash
	}
	if rvsMatchCP(cp, e.RV) &&
		rvsMatchAP(userManagedAP, e.UserManagedAPRV) &&
		rvsMatchNN(userManagedNN, e.UserManagedNNRV) &&
		rvsMatchAP(userAP, e.UserAPRV) &&
		rvsMatchNN(userNN, e.UserNNRV) &&
		e.SpecHash == currentSpecHash {
		return
	}

	c.rebuildEntryFromSources(id, e, cp, userManagedAP, userManagedNN, userAP, userNN)
}

// rvsMatchCP, rvsMatchAP, rvsMatchNN return true when either (a) the object is
// absent and the stored RV is empty, or (b) the object is present and its RV
// matches the stored RV. This lets fast-skip treat "still missing" as a match.
func rvsMatchCP(obj *v1beta1.ContainerProfile, rv string) bool {
	if obj == nil {
		return rv == ""
	}
	return obj.ResourceVersion == rv
}
func rvsMatchAP(obj *v1beta1.ApplicationProfile, rv string) bool {
	if obj == nil {
		return rv == ""
	}
	return obj.ResourceVersion == rv
}
func rvsMatchNN(obj *v1beta1.NetworkNeighborhood, rv string) bool {
	if obj == nil {
		return rv == ""
	}
	return obj.ResourceVersion == rv
}

// rebuildEntryFromSources constructs a fresh CachedContainerProfile from the
// given sources and stores it under `id`. Applies the projection ladder from
// tryPopulateEntry: base CP (or synthesized) → user-managed (ug-) AP+NN →
// label-referenced user overlay AP+NN.
//
// Called by the reconciler when any input ResourceVersion has changed.
func (c *ContainerProfileCacheImpl) rebuildEntryFromSources(
	id string,
	prev *CachedContainerProfile,
	cp *v1beta1.ContainerProfile,
	userManagedAP *v1beta1.ApplicationProfile,
	userManagedNN *v1beta1.NetworkNeighborhood,
	userAP *v1beta1.ApplicationProfile,
	userNN *v1beta1.NetworkNeighborhood,
) {
	pod := c.k8sObjectCache.GetPod(prev.Namespace, prev.PodName)

	// Backfill PodUID when the entry was originally added before the pod
	// appeared in the k8s cache. An empty PodUID on a pre-running init
	// container (where the pod-status ContainerID is also empty) makes
	// isContainerTerminated's (Name, PodUID) fallback match zero and treat
	// the entry as terminated on the next eviction pass. Healing it here
	// lets the next reconcileOnce correctly classify the container.
	podUID := prev.PodUID
	if podUID == "" && pod != nil {
		podUID = string(pod.UID)
	}

	// When the consolidated CP is absent but we still have user-managed /
	// user-defined overlays to project, synthesize an empty base so
	// downstream state display is sensible.
	effectiveCP := cp
	if effectiveCP == nil {
		syntheticName := prev.WorkloadName
		if syntheticName == "" {
			syntheticName = prev.CPName
		}
		effectiveCP = &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      syntheticName,
				Namespace: prev.Namespace,
				Annotations: map[string]string{
					helpersv1.CompletionMetadataKey: helpersv1.Full,
					helpersv1.StatusMetadataKey:     helpersv1.Completed,
				},
			},
		}
	}

	projected := effectiveCP
	// Ladder pass #1: user-managed "ug-" AP + NN.
	if userManagedAP != nil || userManagedNN != nil {
		p, warnings := projectUserProfiles(projected, userManagedAP, userManagedNN, pod, prev.ContainerName)
		projected = p
		c.emitOverlayMetrics(userManagedAP, userManagedNN, warnings)
	}
	// Ladder pass #2: label-referenced user overlay AP + NN.
	var userWarnings []partialProfileWarning
	if userAP != nil || userNN != nil {
		p, w := projectUserProfiles(projected, userAP, userNN, pod, prev.ContainerName)
		projected = p
		userWarnings = w
	}
	c.emitOverlayMetrics(userAP, userNN, userWarnings)

	// Rebuild the call-stack search tree from the projected profile.
	tree := callstackcache.NewCallStackSearchTree()
	for _, stack := range projected.Spec.IdentifiedCallStacks {
		tree.AddCallStack(stack)
	}

	// Project under the current spec.
	spec := c.snapshotSpec()
	applyStart := time.Now()
	projectedCP := Apply(spec, projected, tree)
	if c.cfg.ProfileProjection.DetailedMetricsEnabled {
		c.metricsManager.ObserveProjectionApplyDuration(time.Since(applyStart))
		c.observeMemoryMetrics(projected, projectedCP)
	}

	newEntry := &CachedContainerProfile{
		Projected: projectedCP,
		SpecHash:  projectedCP.SpecHash,
		State:     &objectcache.ProfileState{Completion: effectiveCP.Annotations[helpersv1.CompletionMetadataKey], Status: effectiveCP.Annotations[helpersv1.StatusMetadataKey], Name: effectiveCP.Name},
		CallStackTree:   tree,
		ContainerName:   prev.ContainerName,
		PodName:         prev.PodName,
		Namespace:       prev.Namespace,
		PodUID:          podUID,
		WorkloadID:      prev.WorkloadID,
		CPName:          prev.CPName,
		WorkloadName:    prev.WorkloadName,
		RV:              rvOfCP(cp),
		UserManagedAPRV: rvOfAP(userManagedAP),
		UserManagedNNRV: rvOfNN(userManagedNN),
		UserAPRV:        rvOfAP(userAP),
		UserNNRV:        rvOfNN(userNN),
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

// rvOfCP / rvOfAP / rvOfNN return the object's ResourceVersion or "" when nil.
// Separate typed versions avoid the Go nil-interface trap where a typed-nil
// pointer wrapped in an interface is not == nil.
func rvOfCP(o *v1beta1.ContainerProfile) string {
	if o == nil {
		return ""
	}
	return o.ResourceVersion
}
func rvOfAP(o *v1beta1.ApplicationProfile) string {
	if o == nil {
		return ""
	}
	return o.ResourceVersion
}
func rvOfNN(o *v1beta1.NetworkNeighborhood) string {
	if o == nil {
		return ""
	}
	return o.ResourceVersion
}

// observeMemoryMetrics records per-field entry counts, retention ratios, and
// total byte sizes for the raw vs projected profile. Called only when
// DetailedMetricsEnabled is true.
func (c *ContainerProfileCacheImpl) observeMemoryMetrics(raw *v1beta1.ContainerProfile, pcp *objectcache.ProjectedContainerProfile) {
	type pair struct {
		name string
		raw  []string
		proj objectcache.ProjectedField
	}
	pairs := []pair{
		{"opens", extractOpensPaths(raw), pcp.Opens},
		{"execs", extractExecsPaths(raw), pcp.Execs},
		{"endpoints", extractEndpointPaths(raw), pcp.Endpoints},
		{"capabilities", raw.Spec.Capabilities, pcp.Capabilities},
		{"syscalls", raw.Spec.Syscalls, pcp.Syscalls},
		{"egress_domains", extractEgressDomains(raw), pcp.EgressDomains},
		{"egress_addresses", extractEgressAddresses(raw), pcp.EgressAddresses},
		{"ingress_domains", extractIngressDomains(raw), pcp.IngressDomains},
		{"ingress_addresses", extractIngressAddresses(raw), pcp.IngressAddresses},
	}

	var rawBytes, projBytes float64
	for _, p := range pairs {
		rawCount := float64(len(p.raw))
		retainedCount := float64(len(p.proj.Values) + len(p.proj.Patterns))
		for _, s := range p.raw {
			rawBytes += float64(len(s))
		}
		for s := range p.proj.Values {
			projBytes += float64(len(s))
		}
		for _, s := range p.proj.Patterns {
			projBytes += float64(len(s))
		}
		c.metricsManager.ObserveProfileEntriesRaw(p.name, rawCount)
		c.metricsManager.ObserveProfileEntriesRetained(p.name, retainedCount)
		if rawCount > 0 {
			c.metricsManager.ObserveProfileRetentionRatio(p.name, retainedCount/rawCount)
		}
	}
	c.metricsManager.ObserveProfileRawSize(rawBytes)
	c.metricsManager.ObserveProfileProjectedSize(projBytes)
}

// retryPendingEntries re-issues GetContainerProfile for every containerID that
// was seen on ContainerCallback(Add) but whose CP was not yet in storage. On
// success the entry is promoted into the main cache and removed from pending.
// Exposed for tests.
//
// This preserves the legacy-cache behavior where the periodic "ListProfiles"
// tick recovered containers whose CP showed up after container-start. Without
// this retry, a container whose CP is created asynchronously (the normal
// path, since containerprofilemanager creates the CP after observing behavior)
// would never enter the cache. See component-test regression analysis at
// .omc/plans/containerprofile-cache-component-test-findings.md.
func (c *ContainerProfileCacheImpl) retryPendingEntries(ctx context.Context) {
	type snap struct {
		id string
		p  *pendingContainer
	}
	var work []snap
	c.pending.Range(func(id string, p *pendingContainer) bool {
		if ctx.Err() != nil {
			return false
		}
		work = append(work, snap{id: id, p: p})
		return true
	})
	for _, w := range work {
		if ctx.Err() != nil {
			return
		}
		c.containerLocks.WithLock(w.id, func() {
			// Double-check pending still contains this id (could have been
			// promoted or dropped by a concurrent path).
			if _, still := c.pending.Load(w.id); !still {
				return
			}
			c.tryPopulateEntry(ctx, w.id, w.p.container, w.p.sharedData, w.p.cpName, w.p.workloadName)
		})
	}
}
