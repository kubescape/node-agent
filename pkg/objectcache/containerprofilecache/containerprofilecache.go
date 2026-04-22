// Package containerprofilecache provides a unified, container-keyed cache for ContainerProfile objects.
package containerprofilecache

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/callstackcache"
	"github.com/kubescape/node-agent/pkg/resourcelocks"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// defaultReconcileInterval is the fallback refresh cadence when
// config.ProfilesCacheRefreshRate is zero.
const defaultReconcileInterval = 30 * time.Second

// namespacedName is a minimal identifier for a legacy user-authored CRD
// (ApplicationProfile / NetworkNeighborhood) overlaid on a ContainerProfile.
type namespacedName struct {
	Namespace string
	Name      string
}

// CachedContainerProfile is the per-container cache entry. One entry per live
// containerID, populated on ContainerCallback (Add) and removed on Remove.
//
// Profile may be the raw storage-fetched pointer (Shared=true, fast path) or
// a DeepCopy with user-authored AP/NN overlays merged in (Shared=false).
// entry.Profile is read-only once stored; storage.ProfileClient returns
// fresh-decoded objects per call (thin wrapper over client-go typed client)
// so shared aliasing is safe.
type CachedContainerProfile struct {
	Profile       *v1beta1.ContainerProfile
	State         *objectcache.ProfileState
	CallStackTree *callstackcache.CallStackSearchTree

	ContainerName string
	PodName       string
	Namespace     string
	PodUID        string
	WorkloadID    string

	// UserAPRef / UserNNRef are set when the entry was built with a legacy
	// user-authored AP/NN overlay. Used by the reconciler to re-fetch on
	// refresh and to key deprecation warnings.
	UserAPRef *namespacedName
	UserNNRef *namespacedName

	// CPName is the storage name of the ContainerProfile. Populated at
	// addContainer time so the reconciler can re-fetch without re-querying
	// shared data (which may have been evicted from K8sObjectCache by then).
	CPName string

	Shared   bool   // true iff Profile is the shared storage-fetched pointer (read-only)
	RV       string // ContainerProfile resourceVersion at last load
	UserAPRV string // user-AP resourceVersion at last projection, "" if no overlay
	UserNNRV string // user-NN resourceVersion at last projection, "" if no overlay
}

// pendingContainer captures the minimum state needed to retry the initial
// ContainerProfile GET when the CP is not yet in storage at addContainer time.
// The reconciler iterates pending each tick, re-issues the GET, and promotes
// the entry to `entries` on success. Component-tests regression (PR #788)
// showed the legacy periodic-scan path was load-bearing; this is its
// equivalent in the point-lookup model.
type pendingContainer struct {
	container  *containercollection.Container
	sharedData *objectcache.WatchedContainerData
	cpName     string
}

// ContainerProfileCacheImpl is the unified container-keyed cache for ContainerProfile objects.
type ContainerProfileCacheImpl struct {
	cfg            config.Config
	entries        maps.SafeMap[string, *CachedContainerProfile]
	pending        maps.SafeMap[string, *pendingContainer]
	containerLocks *resourcelocks.ResourceLocks
	storageClient  storage.ProfileClient
	k8sObjectCache objectcache.K8sObjectCache
	metricsManager metricsmanager.MetricsManager

	reconcileEvery    time.Duration
	refreshInProgress atomic.Bool

	// deprecationDedup tracks (kind|ns/name@rv) keys to emit one WARN log
	// per legacy CRD resource-version across the process lifetime.
	deprecationDedup sync.Map
}

// NewContainerProfileCache creates a new ContainerProfileCacheImpl.
// metricsManager may be nil; internally we substitute a no-op so call sites
// don't need nil checks.
func NewContainerProfileCache(cfg config.Config, storageClient storage.ProfileClient, k8sObjectCache objectcache.K8sObjectCache, metricsManager metricsmanager.MetricsManager) *ContainerProfileCacheImpl {
	reconcileEvery := utils.AddJitter(cfg.ProfilesCacheRefreshRate, 10)
	if cfg.ProfilesCacheRefreshRate <= 0 {
		reconcileEvery = defaultReconcileInterval
	}
	if metricsManager == nil {
		metricsManager = metricsmanager.NewMetricsNoop()
	}
	return &ContainerProfileCacheImpl{
		cfg:            cfg,
		containerLocks: resourcelocks.New(),
		storageClient:  storageClient,
		k8sObjectCache: k8sObjectCache,
		metricsManager: metricsManager,
		reconcileEvery: reconcileEvery,
	}
}

// Start begins the periodic reconciler goroutine. The loop evicts entries
// whose container is no longer Running and refreshes live entries' base CP +
// user AP/NN overlays. See reconciler.go for the tick loop and RPC-cost
// characterization.
func (c *ContainerProfileCacheImpl) Start(ctx context.Context) {
	go c.tickLoop(ctx)
}

// ContainerCallback handles container lifecycle events (add/remove). Mirrors
// the shape used by the legacy caches.
func (c *ContainerProfileCacheImpl) ContainerCallback(notif containercollection.PubSubEvent) {
	isHost := utils.IsHostContainer(notif.Container)
	namespace := notif.Container.K8s.Namespace
	if isHost {
		namespace = "host"
	}
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if !isHost && c.cfg.IgnoreContainer(namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
			return
		}
		container := notif.Container
		if isHost {
			containerCopy := *notif.Container
			containerCopy.K8s.Namespace = namespace
			container = &containerCopy
		}
		go c.addContainerWithTimeout(container)
	case containercollection.EventTypeRemoveContainer:
		if !isHost && c.cfg.IgnoreContainer(namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
			return
		}
		go c.deleteContainer(notif.Container.Runtime.ContainerID)
	}
}

// addContainerWithTimeout runs addContainer with a 10-minute cap to prevent
// a stuck storage client from wedging the callback goroutine.
func (c *ContainerProfileCacheImpl) addContainerWithTimeout(container *containercollection.Container) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- c.addContainer(container, ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			logger.L().Error("failed to add container to the container-profile cache", helpers.Error(err))
		}
	case <-ctx.Done():
		logger.L().Error("timeout while adding container to the container-profile cache",
			helpers.String("containerID", container.Runtime.ContainerID),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("namespace", container.K8s.Namespace))
	}
}

// addContainer builds and stores a cache entry for the container: fetches
// the ContainerProfile from storage, optionally fetches user-authored AP/NN
// CRDs, projects them onto a DeepCopy (or fast-paths via shared pointer), and
// builds the call-stack search tree.
func (c *ContainerProfileCacheImpl) addContainer(container *containercollection.Container, ctx context.Context) error {
	containerID := container.Runtime.ContainerID

	return c.containerLocks.WithLockAndError(containerID, func() error {
		sharedData, err := c.waitForSharedContainerData(containerID, ctx)
		if err != nil {
			logger.L().Error("failed to get shared data for container",
				helpers.String("containerID", containerID),
				helpers.Error(err))
			return err
		}

		// GetSlug(false) returns the DETERMINISTIC consolidated-profile slug
		// (stable across agent restarts). containerprofilemanager writes
		// per-tick time-series CPs via GetOneTimeSlug(false) (fresh UUID each
		// call); the storage server consolidates them into a single CP at the
		// GetSlug(false) name for the agent to read. PR #788 initially used
		// GetOneTimeSlug here and every GET 404'd forever — see
		// .omc/plans/containerprofile-cache-component-test-findings.md.
		cpName, err := sharedData.InstanceID.GetSlug(false)
		if err != nil {
			logger.L().Error("failed to compute container profile slug",
				helpers.String("containerID", containerID),
				helpers.Error(err))
			return err
		}

		if populated := c.tryPopulateEntry(containerID, container, sharedData, cpName); !populated {
			// CP not yet in storage. Record a pending entry; the reconciler
			// will retry each tick until the CP shows up or the container
			// stops. This preserves the legacy periodic-scan recovery that
			// kicked in when a CP was created after container-start.
			c.pending.Set(containerID, &pendingContainer{
				container:  container,
				sharedData: sharedData,
				cpName:     cpName,
			})
			c.metricsManager.SetContainerProfileCacheEntries("pending", float64(c.pending.Len()))
		}
		return nil
	})
}

// tryPopulateEntry issues the CP GET (plus any user-AP/NN overlay) and
// installs the cache entry on success. Returns true iff an entry was
// installed. Must be called while holding containerLocks.WithLock(id).
func (c *ContainerProfileCacheImpl) tryPopulateEntry(
	containerID string,
	container *containercollection.Container,
	sharedData *objectcache.WatchedContainerData,
	cpName string,
) bool {
	ns := container.K8s.Namespace

	// Fetch base CP. err/404 is non-fatal; we may still populate from a
	// user-authored overlay when the label is present.
	cp, err := c.storageClient.GetContainerProfile(ns, cpName)
	if err != nil {
		logger.L().Debug("ContainerProfile not yet available",
			helpers.String("containerID", containerID),
			helpers.String("namespace", ns),
			helpers.String("name", cpName),
			helpers.Error(err))
		cp = nil
	}

	// Fix (reviewer #3): if the consolidated CP exists but is still Partial
	// and this container is not PreRunning (i.e. we saw it start fresh after
	// the agent was already up), the partial view belongs to a PREVIOUS
	// container incarnation. Legacy caches explicitly deleted such partials
	// on restart so rule evaluation fell through to "no profile" until a new
	// Full profile arrived. Mirror that: keep pending, retry each tick.
	if cp != nil &&
		cp.Annotations[helpersv1.CompletionMetadataKey] == helpersv1.Partial &&
		!sharedData.PreRunningContainer {
		logger.L().Debug("ContainerProfile is Partial and container is not PreRunning; waiting for Full",
			helpers.String("containerID", containerID),
			helpers.String("namespace", ns),
			helpers.String("name", cpName))
		cp = nil
	}

	// Fetch user-authored legacy CRDs when the pod carries the
	// UserDefinedProfileMetadataKey label. Fix (reviewer #2): fetch
	// independently of the base-CP result, so a container that only has a
	// user-defined profile still gets a cache entry. Recording the refs is
	// gated on successful fetch here (otherwise the projection has no data
	// to merge); the reconciler's refresh path re-fetches on each tick so
	// transient failures are recovered.
	var userAP *v1beta1.ApplicationProfile
	var userNN *v1beta1.NetworkNeighborhood
	overlayName, hasOverlay := container.K8s.PodLabels[helpersv1.UserDefinedProfileMetadataKey]
	if hasOverlay && overlayName != "" {
		if ap, err := c.storageClient.GetApplicationProfile(ns, overlayName); err == nil {
			userAP = ap
		} else {
			logger.L().Debug("user-defined ApplicationProfile not available",
				helpers.String("containerID", containerID),
				helpers.String("namespace", ns),
				helpers.String("name", overlayName),
				helpers.Error(err))
		}
		if nn, err := c.storageClient.GetNetworkNeighborhood(ns, overlayName); err == nil {
			userNN = nn
		} else {
			logger.L().Debug("user-defined NetworkNeighborhood not available",
				helpers.String("containerID", containerID),
				helpers.String("namespace", ns),
				helpers.String("name", overlayName),
				helpers.Error(err))
		}
	}

	// Need SOMETHING to cache. If we have nothing (no base CP, no user CRDs),
	// stay pending and retry on the next tick.
	if cp == nil && userAP == nil && userNN == nil {
		return false
	}

	// User-defined-only path: synthesize an empty base CP so projection has
	// something to merge into. The synthesized CP carries a name/namespace
	// for ProfileState display and a completion=complete annotation so rule
	// evaluation treats it as authoritative (matching legacy behavior where
	// user-authored profiles were stored directly).
	if cp == nil {
		cp = &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      overlayName,
				Namespace: ns,
				Annotations: map[string]string{
					helpersv1.CompletionMetadataKey: helpersv1.Full,
					helpersv1.StatusMetadataKey:     helpersv1.Completed,
				},
			},
		}
	}

	pod := c.k8sObjectCache.GetPod(container.K8s.Namespace, container.K8s.PodName)
	if pod == nil {
		logger.L().Debug("pod not found in k8s cache; skipping pod-aware merge checks",
			helpers.String("containerID", containerID),
			helpers.String("namespace", container.K8s.Namespace),
			helpers.String("podName", container.K8s.PodName))
	}

	entry := c.buildEntry(cp, userAP, userNN, pod, container, sharedData)

	// Fix (reviewer #2): when the overlay label is set, record UserAPRef /
	// UserNNRef even if the initial fetch failed. The refresh loop uses
	// these refs to re-fetch on every tick; without them, a transient 404
	// at add time would permanently lose the overlay.
	if hasOverlay && overlayName != "" {
		if entry.UserAPRef == nil {
			entry.UserAPRef = &namespacedName{Namespace: ns, Name: overlayName}
		}
		if entry.UserNNRef == nil {
			entry.UserNNRef = &namespacedName{Namespace: ns, Name: overlayName}
		}
	}

	c.entries.Set(containerID, entry)
	c.pending.Delete(containerID)
	c.metricsManager.SetContainerProfileCacheEntries("container", float64(c.entries.Len()))
	c.metricsManager.SetContainerProfileCacheEntries("pending", float64(c.pending.Len()))

	logger.L().Debug("ContainerProfileCache - container added",
		helpers.String("containerID", containerID),
		helpers.String("namespace", container.K8s.Namespace),
		helpers.String("podName", container.K8s.PodName),
		helpers.String("cpName", cpName),
		helpers.String("shared", fmt.Sprintf("%v", entry.Shared)))
	return true
}

// buildEntry constructs a CachedContainerProfile, choosing the fast-path
// (shared pointer, no user overlay) or projection path (DeepCopy + merge).
func (c *ContainerProfileCacheImpl) buildEntry(
	cp *v1beta1.ContainerProfile,
	userAP *v1beta1.ApplicationProfile,
	userNN *v1beta1.NetworkNeighborhood,
	pod *corev1.Pod,
	container *containercollection.Container,
	sharedData *objectcache.WatchedContainerData,
) *CachedContainerProfile {
	entry := &CachedContainerProfile{
		ContainerName: container.Runtime.ContainerName,
		PodName:       container.K8s.PodName,
		Namespace:     container.K8s.Namespace,
		WorkloadID:    sharedData.Wlid + "/" + sharedData.InstanceID.GetTemplateHash(),
		CPName:        cp.Name,
		RV:            cp.ResourceVersion,
	}
	if pod != nil {
		entry.PodUID = string(pod.UID)
	}

	if userAP == nil && userNN == nil {
		// Fast path: share the storage-fetched pointer. Do NOT mutate cp;
		// the call-stack tree is built from cp.Spec.IdentifiedCallStacks
		// but the slice is not cleared (read-only invariant).
		entry.Profile = cp
		entry.Shared = true
	} else {
		projected, warnings := projectUserProfiles(cp, userAP, userNN, pod, container.Runtime.ContainerName)
		entry.Profile = projected
		entry.Shared = false

		if userAP != nil {
			entry.UserAPRef = &namespacedName{Namespace: userAP.Namespace, Name: userAP.Name}
			entry.UserAPRV = userAP.ResourceVersion
		}
		if userNN != nil {
			entry.UserNNRef = &namespacedName{Namespace: userNN.Namespace, Name: userNN.Name}
			entry.UserNNRV = userNN.ResourceVersion
		}

		c.emitOverlayMetrics(userAP, userNN, warnings)
	}

	// Build call-stack search tree from entry.Profile.Spec.IdentifiedCallStacks.
	// Shared path: do not mutate the storage-fetched pointer; call stacks
	// stay in the profile but are never read through Profile (only through
	// CallStackTree).
	tree := callstackcache.NewCallStackSearchTree()
	for _, stack := range entry.Profile.Spec.IdentifiedCallStacks {
		tree.AddCallStack(stack)
	}
	entry.CallStackTree = tree

	// ProfileState from CP annotations (Completion/Status) + Name.
	entry.State = &objectcache.ProfileState{
		Completion: cp.Annotations[helpersv1.CompletionMetadataKey],
		Status:     cp.Annotations[helpersv1.StatusMetadataKey],
		Name:       cp.Name,
	}

	return entry
}

// deleteContainer removes a container entry. The per-container lock entry is
// intentionally NOT released: Phase-4 review flagged a race where a concurrent
// addContainer can hold a reference to the old mutex while a subsequent
// GetLock creates a new one, breaking mutual exclusion. Memory cost is bounded
// by the node's container-ID churn (live containers + recently-deleted), so
// keeping stale lock entries is cheaper than getting the atomic-release right.
func (c *ContainerProfileCacheImpl) deleteContainer(id string) {
	c.containerLocks.WithLock(id, func() {
		c.entries.Delete(id)
		c.pending.Delete(id)
	})
	c.metricsManager.SetContainerProfileCacheEntries("container", float64(c.entries.Len()))
	c.metricsManager.SetContainerProfileCacheEntries("pending", float64(c.pending.Len()))
}

// GetContainerProfile returns the cached ContainerProfile pointer for a
// container, or nil if there is no entry. Reports a cache-hit metric.
func (c *ContainerProfileCacheImpl) GetContainerProfile(containerID string) *v1beta1.ContainerProfile {
	if entry, ok := c.entries.Load(containerID); ok && entry != nil && entry.Profile != nil {
		c.metricsManager.ReportContainerProfileCacheHit(true)
		return entry.Profile
	}
	c.metricsManager.ReportContainerProfileCacheHit(false)
	return nil
}

// GetContainerProfileState returns the cached ProfileState for a container
// (completion/status/name). Returns a synthetic error state when the entry
// is missing.
func (c *ContainerProfileCacheImpl) GetContainerProfileState(containerID string) *objectcache.ProfileState {
	if entry, ok := c.entries.Load(containerID); ok && entry != nil && entry.State != nil {
		return entry.State
	}
	return &objectcache.ProfileState{
		Error: fmt.Errorf("container %s not found in container-profile cache", containerID),
	}
}

// GetCallStackSearchTree returns the cached call-stack index for a container,
// or nil if there is no entry or no tree.
func (c *ContainerProfileCacheImpl) GetCallStackSearchTree(containerID string) *callstackcache.CallStackSearchTree {
	if entry, ok := c.entries.Load(containerID); ok && entry != nil {
		return entry.CallStackTree
	}
	return nil
}

// waitForSharedContainerData blocks until K8sObjectCache has shared data for
// the container (populated by containerwatcher) or ctx expires.
func (c *ContainerProfileCacheImpl) waitForSharedContainerData(containerID string, ctx context.Context) (*objectcache.WatchedContainerData, error) {
	return backoff.Retry(ctx, func() (*objectcache.WatchedContainerData, error) {
		if sharedData := c.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

// ReconcileOnce is an exported thin wrapper around reconcileOnce for use by
// out-of-package integration tests (e.g. tests/containerprofilecache/).
// Production code should use tickLoop / Start.
func (c *ContainerProfileCacheImpl) ReconcileOnce(ctx context.Context) {
	c.reconcileOnce(ctx)
}

// SeedEntryForTest directly inserts a CachedContainerProfile entry keyed by
// containerID. Intended exclusively for out-of-package integration tests that
// cannot call the internal addContainer path. Do not call from production code.
func (c *ContainerProfileCacheImpl) SeedEntryForTest(containerID string, entry *CachedContainerProfile) {
	c.entries.Set(containerID, entry)
}

// Ensure ContainerProfileCacheImpl implements the ContainerProfileCache interface.
var _ objectcache.ContainerProfileCache = (*ContainerProfileCacheImpl)(nil)
