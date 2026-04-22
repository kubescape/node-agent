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
	"github.com/kubescape/node-agent/pkg/objectcache/applicationprofilecache/callstackcache"
	"github.com/kubescape/node-agent/pkg/resourcelocks"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
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

// ContainerProfileCacheImpl is the unified container-keyed cache for ContainerProfile objects.
type ContainerProfileCacheImpl struct {
	cfg            config.Config
	entries        maps.SafeMap[string, *CachedContainerProfile]
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

		cpName, err := sharedData.InstanceID.GetOneTimeSlug(false)
		if err != nil {
			logger.L().Error("failed to compute container profile slug",
				helpers.String("containerID", containerID),
				helpers.Error(err))
			return err
		}

		cp, err := c.storageClient.GetContainerProfile(container.K8s.Namespace, cpName)
		if err != nil {
			logger.L().Debug("ContainerProfile not yet available",
				helpers.String("containerID", containerID),
				helpers.String("namespace", container.K8s.Namespace),
				helpers.String("name", cpName),
				helpers.Error(err))
			return nil
		}
		if cp == nil {
			logger.L().Debug("ContainerProfile missing from storage",
				helpers.String("containerID", containerID),
				helpers.String("namespace", container.K8s.Namespace),
				helpers.String("name", cpName))
			return nil
		}

		// Optionally load user-authored legacy CRDs when pod carries the
		// UserDefinedProfileMetadataKey label.
		var userAP *v1beta1.ApplicationProfile
		var userNN *v1beta1.NetworkNeighborhood
		if overlayName, ok := container.K8s.PodLabels[helpersv1.UserDefinedProfileMetadataKey]; ok && overlayName != "" {
			if ap, err := c.storageClient.GetApplicationProfile(container.K8s.Namespace, overlayName); err == nil {
				userAP = ap
			} else {
				logger.L().Debug("user-defined ApplicationProfile not available",
					helpers.String("containerID", containerID),
					helpers.String("namespace", container.K8s.Namespace),
					helpers.String("name", overlayName),
					helpers.Error(err))
			}
			if nn, err := c.storageClient.GetNetworkNeighborhood(container.K8s.Namespace, overlayName); err == nil {
				userNN = nn
			} else {
				logger.L().Debug("user-defined NetworkNeighborhood not available",
					helpers.String("containerID", containerID),
					helpers.String("namespace", container.K8s.Namespace),
					helpers.String("name", overlayName),
					helpers.Error(err))
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
		c.entries.Set(containerID, entry)
		c.metricsManager.SetContainerProfileCacheEntries("container", float64(c.entries.Len()))

		logger.L().Debug("ContainerProfileCache - container added",
			helpers.String("containerID", containerID),
			helpers.String("namespace", container.K8s.Namespace),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("cpName", cpName),
			helpers.String("shared", fmt.Sprintf("%v", entry.Shared)))

		return nil
	})
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

		// Emit full-load metrics + partial-warnings + deprecation WARNs.
		partialByKind := map[string]struct{}{}
		for _, w := range warnings {
			partialByKind[w.Kind] = struct{}{}
			c.metricsManager.ReportContainerProfileLegacyLoad(w.Kind, completenessPartial)
			c.reportDeprecationWarn(w.Kind, w.Namespace, w.Name, w.ResourceVersion,
				fmt.Sprintf("pod has containers missing from user CRD: %v", w.MissingContainers))
		}
		if userAP != nil {
			if _, partial := partialByKind[kindApplication]; !partial {
				c.metricsManager.ReportContainerProfileLegacyLoad(kindApplication, completenessFull)
			}
			c.reportDeprecationWarn(kindApplication, userAP.Namespace, userAP.Name, userAP.ResourceVersion,
				"user-authored ApplicationProfile merged into ContainerProfile")
		}
		if userNN != nil {
			if _, partial := partialByKind[kindNetwork]; !partial {
				c.metricsManager.ReportContainerProfileLegacyLoad(kindNetwork, completenessFull)
			}
			c.reportDeprecationWarn(kindNetwork, userNN.Namespace, userNN.Name, userNN.ResourceVersion,
				"user-authored NetworkNeighborhood merged into ContainerProfile")
		}
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

// deleteContainer removes a container entry and cleans up its per-container
// lock. Critic #2: lock-release happens after the WithLock critical section.
func (c *ContainerProfileCacheImpl) deleteContainer(id string) {
	c.containerLocks.WithLock(id, func() {
		c.entries.Delete(id)
	})
	c.containerLocks.ReleaseLock(id)
	c.metricsManager.SetContainerProfileCacheEntries("container", float64(c.entries.Len()))
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

// Ensure ContainerProfileCacheImpl implements the ContainerProfileCache interface.
var _ objectcache.ContainerProfileCache = (*ContainerProfileCacheImpl)(nil)
