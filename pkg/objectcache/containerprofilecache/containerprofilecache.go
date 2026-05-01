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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// defaultReconcileInterval is the fallback refresh cadence when
// config.ProfilesCacheRefreshRate is zero.
// defaultStorageRPCBudget is the per-call timeout applied by refreshRPC when
// config.StorageRPCBudget is zero.
const (
	defaultReconcileInterval = 30 * time.Second
	defaultStorageRPCBudget  = 5 * time.Second
)

// namespacedName is a minimal identifier for a legacy user-authored CRD
// (ApplicationProfile / NetworkNeighborhood) overlaid on a ContainerProfile.
type namespacedName struct {
	Namespace string
	Name      string
}

// CachedContainerProfile is the per-container cache entry. One entry per live
// containerID, populated on ContainerCallback (Add) and removed on Remove.
//
// Projected holds the compact projected form built by Apply(). The raw
// ContainerProfile is not retained after projection — only the compact form is
// stored so the raw pointer can be GC'd.
type CachedContainerProfile struct {
	Projected     *objectcache.ProjectedContainerProfile
	SpecHash      string // mirrors Projected.SpecHash; used for staleness checks
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

	// WorkloadName is the per-workload slug used to fetch the workload-level
	// ApplicationProfile / NetworkNeighborhood (primary data source while the
	// storage-side consolidated CP isn't publicly queryable) and, with the
	// "ug-" prefix, the user-managed AP/NN. Populated at addContainer time.
	WorkloadName string

	RV              string // ContainerProfile resourceVersion at last load
	UserManagedAPRV string // user-managed AP (ug-<workload>) RV at last projection, "" if absent
	UserManagedNNRV string // user-managed NN (ug-<workload>) RV at last projection, "" if absent
	UserAPRV        string // user-AP (label-referenced) resourceVersion at last projection, "" if no overlay
	UserNNRV        string // user-NN (label-referenced) resourceVersion at last projection, "" if no overlay
}

// pendingContainer captures the minimum state needed to retry the initial
// ContainerProfile GET when the CP is not yet in storage at addContainer time.
// The reconciler iterates pending each tick, re-issues the GET, and promotes
// the entry to `entries` on success. Component-tests regression (PR #788)
// showed the legacy periodic-scan path was load-bearing; this is its
// equivalent in the point-lookup model.
type pendingContainer struct {
	container    *containercollection.Container
	sharedData   *objectcache.WatchedContainerData
	cpName       string
	workloadName string
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
	rpcBudget         time.Duration
	refreshInProgress atomic.Bool

	// deprecationDedup tracks (kind|ns/name@rv) keys to emit one WARN log
	// per legacy CRD resource-version across the process lifetime.
	deprecationDedup sync.Map

	// Projection spec — installed by SetProjectionSpec when rulemanager loads rules.
	currentSpecMu  sync.RWMutex
	currentSpec    *objectcache.RuleProjectionSpec
	specGeneration atomic.Int64  // bumped on each distinct spec hash change
	nudge          chan struct{} // buffered cap 1; signals reconciler on spec change
	refreshPending atomic.Bool   // set when a nudge arrives while refresh is running
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
	rpcBudget := cfg.StorageRPCBudget
	if rpcBudget <= 0 {
		rpcBudget = defaultStorageRPCBudget
	}
	return &ContainerProfileCacheImpl{
		cfg:            cfg,
		containerLocks: resourcelocks.New(),
		storageClient:  storageClient,
		k8sObjectCache: k8sObjectCache,
		metricsManager: metricsManager,
		reconcileEvery: reconcileEvery,
		rpcBudget:      rpcBudget,
		nudge:          make(chan struct{}, 1),
	}
}

func shouldLogOptionalUserManagedFetchError(err error) bool {
	return err != nil && !apierrors.IsNotFound(err)
}

// refreshRPC calls fn with a context bounded by c.rpcBudget, enforcing a
// per-call SLO so a slow API server cannot stall a full reconciler burst.
func (c *ContainerProfileCacheImpl) refreshRPC(ctx context.Context, fn func(context.Context) error) error {
	rpcCtx, cancel := context.WithTimeout(ctx, c.rpcBudget)
	defer cancel()
	return fn(rpcCtx)
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
		// Skip the ignore check on Remove: a container added before its pod
		// labels matched the ignore filter would otherwise leak in the cache.
		// The reconciler eviction path is the safety net, but a Remove event
		// should always clean up regardless of current label state.
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

		// Names we need:
		//   cpName       = per-container stable slug, for the consolidated CP.
		//                  Kept for forward-compat; current storage does not
		//                  publish a queryable consolidated CP at this name,
		//                  so we treat a 404 as "not yet".
		//   workloadName = per-workload stable slug, where the server-side
		//                  aggregation publishes the ApplicationProfile and
		//                  NetworkNeighborhood CRs. Legacy caches read these
		//                  directly; the new cache does the same while the
		//                  server-side consolidated-CP plumbing matures.
		cpName, err := sharedData.InstanceID.GetSlug(false)
		if err != nil {
			logger.L().Error("failed to compute container profile slug",
				helpers.String("containerID", containerID),
				helpers.Error(err))
			return err
		}
		workloadName, err := sharedData.InstanceID.GetSlug(true)
		if err != nil {
			logger.L().Error("failed to compute workload profile slug",
				helpers.String("containerID", containerID),
				helpers.Error(err))
			return err
		}

		if populated := c.tryPopulateEntry(ctx, containerID, container, sharedData, cpName, workloadName); !populated {
			// No profile data available yet (neither consolidated CP nor
			// workload AP/NN have landed in storage). Record a pending entry;
			// the reconciler will retry each tick until data shows up or the
			// container stops. This preserves the legacy periodic-scan
			// recovery that kicked in when profiles were created after
			// container-start.
			c.pending.Set(containerID, &pendingContainer{
				container:    container,
				sharedData:   sharedData,
				cpName:       cpName,
				workloadName: workloadName,
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
	ctx context.Context,
	containerID string,
	container *containercollection.Container,
	sharedData *objectcache.WatchedContainerData,
	cpName, workloadName string,
) bool {
	ns := container.K8s.Namespace

	// Fetch consolidated ContainerProfile. The storage server aggregates the
	// per-tick time-series CPs (written by containerprofilemanager at names
	// ending in a random UUID suffix) into a consolidated CP at the stable
	// name returned by GetSlug(false). Until that aggregation runs the Get
	// returns 404 — we record pending and the reconciler retries on each
	// tick.
	var (
		cp    *v1beta1.ContainerProfile
		cpErr error
	)
	_ = c.refreshRPC(ctx, func(rctx context.Context) error {
		cp, cpErr = c.storageClient.GetContainerProfile(rctx, ns, cpName)
		return cpErr
	})
	if cpErr != nil {
		logger.L().Debug("ContainerProfile not yet available",
			helpers.String("containerID", containerID),
			helpers.String("namespace", ns),
			helpers.String("name", cpName),
			helpers.Error(cpErr))
		cp = nil
	}

	// Fetch user-managed AP / NN published at "ug-<workloadName>". Legacy
	// caches auto-detected these via the `kubescape.io/managed-by: User`
	// annotation and merged them on top of the base profile; we read them
	// directly by their well-known name instead, avoiding a List and an
	// annotation filter. Both are optional: nil on 404.
	var userManagedAP *v1beta1.ApplicationProfile
	var userManagedNN *v1beta1.NetworkNeighborhood
	if workloadName != "" {
		ugName := helpersv1.UserApplicationProfilePrefix + workloadName
		var ugAPErr error
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			userManagedAP, ugAPErr = c.storageClient.GetApplicationProfile(rctx, ns, ugName)
			return ugAPErr
		})
		if ugAPErr != nil {
			if shouldLogOptionalUserManagedFetchError(ugAPErr) {
				logger.L().Debug("failed to fetch user-managed ApplicationProfile",
					helpers.String("containerID", containerID),
					helpers.String("namespace", ns),
					helpers.String("name", ugName),
					helpers.Error(ugAPErr))
			}
			userManagedAP = nil
		}
		ugNNName := helpersv1.UserNetworkNeighborhoodPrefix + workloadName
		var ugNNErr error
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			userManagedNN, ugNNErr = c.storageClient.GetNetworkNeighborhood(rctx, ns, ugNNName)
			return ugNNErr
		})
		if ugNNErr != nil {
			if shouldLogOptionalUserManagedFetchError(ugNNErr) {
				logger.L().Debug("failed to fetch user-managed NetworkNeighborhood",
					helpers.String("containerID", containerID),
					helpers.String("namespace", ns),
					helpers.String("name", ugNNName),
					helpers.Error(ugNNErr))
			}
			userManagedNN = nil
		}
	}

	// Fix (reviewer #3): if the consolidated CP is still Partial and this
	// container is not PreRunning (i.e. we saw it start fresh after the
	// agent was already up), the partial view belongs to a PREVIOUS container
	// incarnation. Legacy caches explicitly deleted such partials on restart
	// so rule evaluation fell through to "no profile" until a new Full
	// profile arrived. Mirror that: keep pending, retry each tick.
	if !sharedData.PreRunningContainer {
		if cp != nil && cp.Annotations[helpersv1.CompletionMetadataKey] == helpersv1.Partial {
			cp = nil
		}
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
		var userAPErr error
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			userAP, userAPErr = c.storageClient.GetApplicationProfile(rctx, ns, overlayName)
			return userAPErr
		})
		if userAPErr != nil {
			logger.L().Debug("user-defined ApplicationProfile not available",
				helpers.String("containerID", containerID),
				helpers.String("namespace", ns),
				helpers.String("name", overlayName),
				helpers.Error(userAPErr))
			userAP = nil
		}
		var userNNErr error
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			userNN, userNNErr = c.storageClient.GetNetworkNeighborhood(rctx, ns, overlayName)
			return userNNErr
		})
		if userNNErr != nil {
			logger.L().Debug("user-defined NetworkNeighborhood not available",
				helpers.String("containerID", containerID),
				helpers.String("namespace", ns),
				helpers.String("name", overlayName),
				helpers.Error(userNNErr))
			userNN = nil
		}
	}

	// Need SOMETHING to cache. If we have nothing, stay pending and retry.
	if cp == nil && userManagedAP == nil && userManagedNN == nil && userAP == nil && userNN == nil {
		return false
	}

	// When no consolidated CP is available, synthesize an empty CP named
	// after the workload so downstream state display is sensible. Projection
	// below merges user-managed + user-defined overlay onto this base.
	if cp == nil {
		syntheticName := workloadName
		if syntheticName == "" {
			syntheticName = overlayName
		}
		cp = &v1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      syntheticName,
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

	// User-managed projection pass (published at the
	// "ug-<workloadName>" well-known name). Legacy caches auto-merged these
	// in handleUserManagedProfile after detecting the managed-by annotation;
	// here we always union in whatever's published at the convention name.
	// This is what Test_12_MergingProfilesTest / Test_13_MergingNetworkNeighborhoodTest
	// exercise: rules must alert on events absent from the merged base+user-managed
	// profile.
	userManagedApplied := userManagedAP != nil || userManagedNN != nil
	if userManagedApplied {
		projected, warnings := projectUserProfiles(cp, userManagedAP, userManagedNN, pod, container.Runtime.ContainerName)
		cp = projected
		c.emitOverlayMetrics(userManagedAP, userManagedNN, warnings)
	}

	entry := c.buildEntry(cp, userAP, userNN, pod, container, sharedData)
	// Override CPName with the real consolidated-CP slug. buildEntry sets
	// CPName from cp.Name, but when cp was synthesized above (no consolidated
	// CP in storage yet), cp.Name is the workloadName/overlayName — NOT the
	// GetSlug(false) name refreshOneEntry must GET. Without this override,
	// refresh queries the synthetic name, always 404s, and the fast-skip
	// keeps the synthetic entry forever (stored RV is "" == absent-match).
	entry.CPName = cpName
	// Fill in user-managed bookkeeping so refreshOneEntry can re-fetch these
	// sources on every tick. WorkloadName is the "ug-" lookup prefix.
	entry.WorkloadName = workloadName
	if userManagedAP != nil {
		entry.UserManagedAPRV = userManagedAP.ResourceVersion
	}
	if userManagedNN != nil {
		entry.UserManagedNNRV = userManagedNN.ResourceVersion
	}

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
		helpers.String("cpName", cpName))
	return true
}

// buildEntry constructs a CachedContainerProfile by applying user overlays then
// projecting the merged profile under the current spec. The raw profile pointer
// is released after projection; only the compact ProjectedContainerProfile is
// stored.
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

	// Apply label-referenced user overlay (if any).
	userMerged := cp
	if userAP != nil || userNN != nil {
		merged, warnings := projectUserProfiles(cp, userAP, userNN, pod, container.Runtime.ContainerName)
		userMerged = merged
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

	// Build call-stack search tree.
	tree := callstackcache.NewCallStackSearchTree()
	for _, stack := range userMerged.Spec.IdentifiedCallStacks {
		tree.AddCallStack(stack)
	}
	entry.CallStackTree = tree

	// Project under the current spec.
	spec := c.snapshotSpec()
	projected := Apply(spec, userMerged, tree)
	entry.Projected = projected
	entry.SpecHash = projected.SpecHash

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

// GetProjectedContainerProfile returns the projected profile for a container,
// or nil if there is no entry. Reports a cache-hit metric.
func (c *ContainerProfileCacheImpl) GetProjectedContainerProfile(containerID string) *objectcache.ProjectedContainerProfile {
	if entry, ok := c.entries.Load(containerID); ok && entry != nil && entry.Projected != nil {
		c.metricsManager.ReportContainerProfileCacheHit(true)
		return entry.Projected
	}
	c.metricsManager.ReportContainerProfileCacheHit(false)
	return nil
}

// SetProjectionSpec installs a new compiled spec. Idempotent: no-op when the
// spec hash matches the currently-installed one. On change: stores the spec,
// bumps specGeneration, and sends a non-blocking nudge to the reconciler.
// Never blocks on the reconciler (rulemanager calls this inline).
func (c *ContainerProfileCacheImpl) SetProjectionSpec(spec objectcache.RuleProjectionSpec) {
	c.currentSpecMu.Lock()
	if c.currentSpec != nil && c.currentSpec.Hash == spec.Hash {
		c.currentSpecMu.Unlock()
		return
	}
	c.currentSpec = &spec
	c.currentSpecMu.Unlock()

	c.specGeneration.Add(1)

	if c.cfg.ProfileProjection.DetailedMetricsEnabled {
		c.metricsManager.IncProjectionSpecHashChange()
	}

	select {
	case c.nudge <- struct{}{}:
	default:
	}
}

// snapshotSpec returns a pointer to the currently-installed spec under RLock.
// Returns nil when no spec has been installed yet; Apply treats nil as an
// empty spec (all surfaces drop everything).
func (c *ContainerProfileCacheImpl) snapshotSpec() *objectcache.RuleProjectionSpec {
	c.currentSpecMu.RLock()
	defer c.currentSpecMu.RUnlock()
	return c.currentSpec
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

// Ensure ContainerProfileCacheImpl implements the ContainerProfileCache interface.
var _ objectcache.ContainerProfileCache = (*ContainerProfileCacheImpl)(nil)
