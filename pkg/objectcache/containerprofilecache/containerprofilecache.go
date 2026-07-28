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

	// UserCPRef is set when the user-defined-profile label names a single
	// user-authored ContainerProfile (the migrated "new way"), which is used
	// as the authoritative base for the container. It is the only user-defined
	// source — the legacy AP/NN overlay is no longer supported. Used by the
	// reconciler to re-fetch on refresh.
	UserCPRef *namespacedName

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
	UserManagedCPRV string // user-managed CP (ug-<workload>) RV at last projection, "" if absent
	UserCPRV        string // user-defined ContainerProfile (label-referenced) RV at last load, "" if not used
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

	reconcileEvery time.Duration
	rpcBudget      time.Duration
	refreshInProgress atomic.Bool

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
	c := &ContainerProfileCacheImpl{
		cfg:            cfg,
		containerLocks: resourcelocks.New(),
		storageClient:  storageClient,
		k8sObjectCache: k8sObjectCache,
		metricsManager: metricsManager,
		reconcileEvery: reconcileEvery,
		rpcBudget:      rpcBudget,
		nudge:          make(chan struct{}, 1),
	}
	// Pre-initialize SafeMap internal maps: Load() reads m.items == nil without
	// a lock while Set() writes m.items under a write lock, causing a data race
	// on the first concurrent access to a zero-value SafeMap.
	c.entries.Set("", nil)
	c.entries.Delete("")
	c.pending.Set("", nil)
	c.pending.Delete("")
	return c
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


	// User-managed overlay: the migrated "ug-<workloadName>" ContainerProfile
	// (annotated managed-by: User), unioned on top of the base. This replaces the
	// legacy ug- ApplicationProfile + NetworkNeighborhood pair. Optional: nil on 404.
	var userManagedCP *v1beta1.ContainerProfile
	if workloadName != "" {
		// UserApplicationProfilePrefix is the shared "ug-" user-managed prefix.
		ugCPName := helpersv1.UserApplicationProfilePrefix + workloadName
		var ugCPErr error
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			userManagedCP, ugCPErr = c.storageClient.GetContainerProfile(rctx, ns, ugCPName)
			return ugCPErr
		})
		if ugCPErr != nil {
			if shouldLogOptionalUserManagedFetchError(ugCPErr) {
				logger.L().Debug("failed to fetch user-managed ContainerProfile",
					helpers.String("containerID", containerID),
					helpers.String("namespace", ns),
					helpers.String("name", ugCPName),
					helpers.Error(ugCPErr))
			}
			userManagedCP = nil
		}
	}

	// Only cache profiles whose status is terminal (Completed or TooLarge).
	// Learning/ready profiles are still being written; caching them would let
	// rules fire against incomplete data. TooLarge is terminal: the manager
	// stopped collecting but the truncated data is still valid for detection.
	// Return false so the synthetic-CP fallback below does not bypass the gate.
	if cp != nil && !isTerminalCPStatus(cp.Annotations[helpersv1.StatusMetadataKey]) {
		logger.L().Debug("tryPopulateEntry: CP status not terminal; keeping pending",
			helpers.String("containerID", containerID),
			helpers.String("namespace", ns),
			helpers.String("status", cp.Annotations[helpersv1.StatusMetadataKey]))
		return false
	}

	// Fetch the user-authored ContainerProfile when the pod carries the
	// UserDefinedProfileMetadataKey label. Migration (#862/#864) is a HARD
	// cutover: the label now names a single user-authored ContainerProfile —
	// the unified replacement for the legacy AP+NN overlay pair, which is no
	// longer supported. The CP is authoritative and needs no overlay merge. On
	// a fetch error (transient, or the CP hasn't landed yet) it is left nil and
	// the container stays pending; UserCPRef — recorded unconditionally below —
	// drives the reconciler to retry the CP on every tick until it materialises.
	var userDefinedCP *v1beta1.ContainerProfile
	overlayName, hasOverlay := container.K8s.PodLabels[helpersv1.UserDefinedProfileMetadataKey]
	// resolvedOverlayName is the ContainerProfile name the label ultimately
	// resolves to; it is recorded in entry.UserCPRef so refreshOneEntry re-fetches
	// the SAME object every tick. It defaults to the bare label value — the
	// single-container convention and the safest retry target when the
	// per-container fetch does not cleanly succeed.
	resolvedOverlayName := overlayName
	if hasOverlay && overlayName != "" {
		// Per-container binding (review finding on node-agent#864): a
		// multi-container pod shares one label value but each container is
		// profiled independently, so its authored ContainerProfile is published
		// at "<overlay>-<containerName>". Try that per-container name first; on a
		// genuine NotFound fall back to the bare "<overlay>" (single-container
		// pods). A transient error is NOT a fallback trigger — the CP is left nil
		// for this tick and the bare name stays the retry target.
		perContainerName := overlayName + "-" + container.Runtime.ContainerName
		var userCPErr error
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			userDefinedCP, userCPErr = c.storageClient.GetContainerProfile(rctx, ns, perContainerName)
			return userCPErr
		})
		switch {
		case userCPErr == nil && userDefinedCP != nil:
			resolvedOverlayName = perContainerName
		case apierrors.IsNotFound(userCPErr):
			// Fall back to the bare overlay name (single-container convention).
			userDefinedCP = nil
			var bareErr error
			_ = c.refreshRPC(ctx, func(rctx context.Context) error {
				userDefinedCP, bareErr = c.storageClient.GetContainerProfile(rctx, ns, overlayName)
				return bareErr
			})
			if bareErr != nil {
				logger.L().Debug("user-defined ContainerProfile not available",
					helpers.String("containerID", containerID),
					helpers.String("namespace", ns),
					helpers.String("name", overlayName),
					helpers.Error(bareErr))
				userDefinedCP = nil
			}
		default:
			// Transient error on the per-container fetch: keep probing the bare
			// name on later ticks (the common single-container recovery target).
			logger.L().Debug("user-defined ContainerProfile not available",
				helpers.String("containerID", containerID),
				helpers.String("namespace", ns),
				helpers.String("name", perContainerName),
				helpers.Error(userCPErr))
			userDefinedCP = nil
		}
	}

	// A label-referenced ContainerProfile must be USER-AUTHORED, not a learned
	// one. A learned CP carries lifecycle annotations (status/completion); an
	// authored one carries none. If the label resolves to a learned CP, ignore
	// it — otherwise its real state is overwritten with Completed/Full below and
	// a still-learning profile would be enforced as complete (false positives).
	if userDefinedCP != nil {
		if _, learned := userDefinedCP.Annotations[helpersv1.StatusMetadataKey]; learned {
			logger.L().Warning("user-defined-profile label resolves to a learned ContainerProfile; ignoring it",
				helpers.String("containerID", containerID),
				helpers.String("namespace", ns),
				helpers.String("name", overlayName))
			userDefinedCP = nil
		}
	}

	// Need SOMETHING to cache. If we have nothing, stay pending and retry.
	if cp == nil && userDefinedCP == nil && userManagedCP == nil {
		// Visibility for the upgrade path: a workload whose user-defined-profile
		// label is set but resolves to nothing (e.g. still-legacy AP/NN that are
		// no longer read) would otherwise pend forever with only a Debug trace.
		// Warn once — before the container enters `pending` — so the periodic
		// retry doesn't spam.
		if hasOverlay && overlayName != "" && !c.pending.Has(containerID) {
			logger.L().Warning("user-defined-profile label set but no ContainerProfile resolved; container has no profile (legacy ApplicationProfile/NetworkNeighborhood are no longer read)",
				helpers.String("containerID", containerID),
				helpers.String("namespace", ns),
				helpers.String("name", overlayName))
		}
		return false
	}

	// Capture the LEARNED CP's ResourceVersion before cp is repointed at the
	// authored profile. entry.RV must track the object entry.CPName points at
	// (the learned slug). If it held the authored RV instead, refreshOneEntry
	// would compare it against a GET on the learned slug — which 404s for a
	// user-defined container (learning is suppressed) — and read that 404 as a
	// transient error, freezing the entry so authored-CP edits are never picked
	// up (review finding on node-agent#864).
	learnedRV := ""
	if cp != nil {
		learnedRV = cp.ResourceVersion
	}

	// A user-defined ContainerProfile is authoritative for this container: it is
	// the migrated replacement for the AP+NN overlay, so it becomes the base
	// (the ug- user-managed pass may still union on top). Learning is suppressed
	// for user-defined containers, so no consolidated CP competes with it.
	if userDefinedCP != nil {
		cp = userDefinedCP
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

	// User-managed "ug-" overlay pass: union the migrated ug- ContainerProfile
	// on top of the base. (Legacy AP/NN overlay merge removed.)
	if userManagedCP != nil {
		cp = projectUserManagedCP(cp, userManagedCP)
	}

	entry := c.buildEntry(cp, pod, container, sharedData)
	// Override CPName with the real consolidated-CP slug. buildEntry sets
	// CPName from cp.Name, but when cp was synthesized above (no consolidated
	// CP in storage yet), cp.Name is the workloadName/overlayName — NOT the
	// GetSlug(false) name refreshOneEntry must GET. Without this override,
	// refresh queries the synthetic name, always 404s, and the fast-skip
	// keeps the synthetic entry forever (stored RV is "" == absent-match).
	entry.CPName = cpName
	// buildEntry derives RV from whatever it projected — the authored CP when one
	// was adopted. refreshOneEntry compares entry.RV against a GET on entry.CPName
	// (the learned slug), so leaving the authored RV here makes the permanent 404
	// on that slug look transient and freezes the entry. Track the learned RV.
	entry.RV = learnedRV
	// Fill in user-managed bookkeeping so refreshOneEntry can re-fetch these
	// sources on every tick. WorkloadName is the "ug-" lookup prefix.
	entry.WorkloadName = workloadName
	if userManagedCP != nil {
		entry.UserManagedCPRV = userManagedCP.ResourceVersion
	}

	// When the overlay label is set, ALWAYS record UserCPRef so the reconciler
	// keeps probing for the user-authored ContainerProfile on every tick — even
	// when this first fetch failed (transient error, or the CP simply hasn't
	// landed yet). refreshOneEntry only re-fetches the user-defined CP
	// `if e.UserCPRef != nil`; without this unconditional assignment a transient
	// error at add time would leave the container without an authored profile
	// until it restarts. There is no legacy AP/NN fallback anymore — the CP is
	// the only user-defined source.
	if hasOverlay && overlayName != "" {
		entry.UserCPRef = &namespacedName{Namespace: ns, Name: resolvedOverlayName}
		if userDefinedCP != nil {
			entry.UserCPRV = userDefinedCP.ResourceVersion
			// A user-authored profile is authoritative and complete by
			// definition — it carries no learning-lifecycle status/completion
			// annotations (those are meaningless on an authored profile). Force
			// the terminal state so the rule engine enforces it (rule_manager
			// gates on Completed+Full).
			entry.State = &objectcache.ProfileState{
				Status:     helpersv1.Completed,
				Completion: helpersv1.Full,
				Name:       userDefinedCP.Name,
			}
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

	// The base is authoritative as-is: the user-defined overlay is now a whole
	// ContainerProfile adopted directly as `cp` (no AP/NN merge), and the
	// user-managed "ug-" merge already ran on `cp` before buildEntry is called.
	userMerged := cp

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

// NotifyContainerCompleted is called by containerprofilemanager when it writes a
// CP with status="completed". If the container is still pending it launches a
// bounded retry goroutine (up to 5 attempts × 3 s) so the cache entry is
// promoted within seconds of the consolidation cycle completing, without waiting
// for the next 30 s reconciler tick.
func (c *ContainerProfileCacheImpl) NotifyContainerCompleted(containerID string) {
	p, pending := c.pending.Load(containerID)
	if !pending {
		return
	}
	go func() {
		for i := 0; i < 20; i++ {
			if i > 0 {
				time.Sleep(3 * time.Second)
			}
			if _, still := c.pending.Load(containerID); !still {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), c.rpcBudget)
			var promoted bool
			c.containerLocks.WithLock(containerID, func() {
				if _, still := c.pending.Load(containerID); still {
					promoted = c.tryPopulateEntry(ctx, containerID, p.container, p.sharedData, p.cpName, p.workloadName)
				}
			})
			cancel()
			if promoted {
				return
			}
		}
	}()
}

// isTerminalCPStatus reports whether the CP status annotation value represents
// a terminal state that the cache should accept. Terminal states are:
//   - Completed: learning period finished normally.
//   - TooLarge: manager stopped collecting because the profile grew too large;
//     the truncated data is still valid for rule evaluation.
//
// Learning ("ready") is not terminal — the CP is still being written.
func isTerminalCPStatus(status string) bool {
	return status == helpersv1.Completed || status == helpersv1.TooLarge
}

// Ensure ContainerProfileCacheImpl implements the ContainerProfileCache interface.
var _ objectcache.ContainerProfileCache = (*ContainerProfileCacheImpl)(nil)
