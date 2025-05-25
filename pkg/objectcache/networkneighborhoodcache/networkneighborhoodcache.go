package networkneighborhoodcache

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	versioned "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContainerInfo holds essential container metadata for network neighborhood mapping
type ContainerInfo struct {
	ContainerID          string
	WorkloadID           string
	InstanceTemplateHash string
	Namespace            string
}

// NetworkNeighborhoodKey represents a unique network neighborhood identifier
type NetworkNeighborhoodKey string

func (nnk NetworkNeighborhoodKey) String() string {
	return string(nnk)
}

// NetworkNeighborhoodCache implements efficient network neighborhood caching with periodic updates
type NetworkNeighborhoodCache struct {
	// Configuration
	cfg            config.Config
	storageClient  versioned.SpdxV1beta1Interface
	k8sObjectCache objectcache.K8sObjectCache
	updateInterval time.Duration

	// Core mappings
	workloadNeighborhoods maps.SafeMap[string, *v1beta1.NetworkNeighborhood]
	workloadStates        maps.SafeMap[string, *objectcache.ProfileState]
	containerInfo         maps.SafeMap[string, *ContainerInfo]
	namespaceContainers   maps.SafeMap[string, mapset.Set[string]]

	// User-managed network neighborhood tracking
	userNeighborhoodIdentifiers maps.SafeMap[NetworkNeighborhoodKey, string]

	// Synchronization
	mu               sync.RWMutex
	updateInProgress bool
	updateMu         sync.Mutex
}

// NewNetworkNeighborhoodCache creates a new cache instance with jittered update intervals
func NewNetworkNeighborhoodCache(
	cfg config.Config,
	storageClient versioned.SpdxV1beta1Interface,
	k8sObjectCache objectcache.K8sObjectCache,
) *NetworkNeighborhoodCache {
	return &NetworkNeighborhoodCache{
		cfg:                         cfg,
		storageClient:               storageClient,
		k8sObjectCache:              k8sObjectCache,
		updateInterval:              utils.AddJitter(cfg.ProfilesCacheRefreshRate, 10),
		workloadNeighborhoods:       maps.SafeMap[string, *v1beta1.NetworkNeighborhood]{},
		workloadStates:              maps.SafeMap[string, *objectcache.ProfileState]{},
		containerInfo:               maps.SafeMap[string, *ContainerInfo]{},
		namespaceContainers:         maps.SafeMap[string, mapset.Set[string]]{},
		userNeighborhoodIdentifiers: maps.SafeMap[NetworkNeighborhoodKey, string]{},
	}
}

// Start initiates the periodic network neighborhood update process
func (nnc *NetworkNeighborhoodCache) Start(ctx context.Context) {
	go nnc.runPeriodicUpdates(ctx)
}

// runPeriodicUpdates manages the periodic network neighborhood refresh cycle
func (nnc *NetworkNeighborhoodCache) runPeriodicUpdates(ctx context.Context) {
	ticker := time.NewTicker(nnc.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if nnc.shouldSkipUpdate() {
				logger.L().Debug("skipping network neighborhood update: previous update still in progress")
				continue
			}

			nnc.setUpdateInProgress(true)
			nnc.refreshAllNeighborhoods(ctx)
			nnc.setUpdateInProgress(false)

		case <-ctx.Done():
			logger.L().Info("NetworkNeighborhoodCache periodic update stopped")
			return
		}
	}
}

// shouldSkipUpdate checks if an update is already in progress
func (nnc *NetworkNeighborhoodCache) shouldSkipUpdate() bool {
	nnc.updateMu.Lock()
	defer nnc.updateMu.Unlock()
	return nnc.updateInProgress
}

// setUpdateInProgress safely sets the update progress flag
func (nnc *NetworkNeighborhoodCache) setUpdateInProgress(inProgress bool) {
	nnc.updateMu.Lock()
	defer nnc.updateMu.Unlock()
	nnc.updateInProgress = inProgress
}

// refreshAllNeighborhoods fetches and updates all network neighborhoods from storage
func (nnc *NetworkNeighborhoodCache) refreshAllNeighborhoods(ctx context.Context) {
	namespaces := nnc.getActiveNamespaces()

	for namespace, containerSet := range namespaces {
		if containerSet.Cardinality() == 0 {
			continue
		}
		nnc.refreshNamespaceNeighborhoods(ctx, namespace, containerSet)
	}
}

// getActiveNamespaces returns a snapshot of namespace to container mappings
func (nnc *NetworkNeighborhoodCache) getActiveNamespaces() map[string]mapset.Set[string] {
	nnc.mu.RLock()
	defer nnc.mu.RUnlock()

	namespaces := make(map[string]mapset.Set[string])
	nnc.namespaceContainers.Range(func(namespace string, containerSet mapset.Set[string]) bool {
		namespaces[namespace] = containerSet
		return true
	})
	return namespaces
}

// refreshNamespaceNeighborhoods updates network neighborhoods for a specific namespace
func (nnc *NetworkNeighborhoodCache) refreshNamespaceNeighborhoods(ctx context.Context, namespace string, containerSet mapset.Set[string]) {
	neighborhoodList, err := nnc.storageClient.NetworkNeighborhoods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.L().Error("failed to list network neighborhoods",
			helpers.String("namespace", namespace),
			helpers.Error(err))
		return
	}

	for _, neighborhood := range neighborhoodList.Items {
		if nnc.isUserManagedNeighborhood(&neighborhood) {
			nnc.handleUserManagedNeighborhood(&neighborhood)
		} else {
			nnc.handleStandardNeighborhood(ctx, &neighborhood, containerSet)
		}
	}
}

// handleStandardNeighborhood processes regular (non-user-managed) network neighborhoods
func (nnc *NetworkNeighborhoodCache) handleStandardNeighborhood(ctx context.Context, neighborhood *v1beta1.NetworkNeighborhood, containerSet mapset.Set[string]) {
	workloadID := neighborhood.Annotations[helpersv1.WlidMetadataKey]
	if workloadID == "" {
		return
	}

	// Always update profile state
	profileState := &objectcache.ProfileState{
		Completion: neighborhood.Annotations[helpersv1.CompletionMetadataKey],
		Status:     neighborhood.Annotations[helpersv1.StatusMetadataKey],
		Name:       neighborhood.Name,
		Error:      nil,
	}
	nnc.workloadStates.Set(workloadID, profileState)

	// Only process completed neighborhoods
	if neighborhood.Annotations[helpersv1.StatusMetadataKey] != helpersv1.Completed {
		return
	}

	if !nnc.isWorkloadInUse(workloadID, neighborhood.Labels[helpersv1.TemplateHashKey], containerSet) {
		return
	}

	if nnc.shouldSkipNeighborhoodUpdate(workloadID, neighborhood) {
		return
	}

	fullNeighborhood, err := nnc.fetchFullNeighborhood(ctx, neighborhood)
	if err != nil {
		profileState.Error = err
		nnc.workloadStates.Set(workloadID, profileState)
		return
	}

	nnc.updateNeighborhood(workloadID, fullNeighborhood)
}

// isWorkloadInUse checks if a workload ID is currently used by any container
func (nnc *NetworkNeighborhoodCache) isWorkloadInUse(workloadID, templateHash string, containerSet mapset.Set[string]) bool {
	for containerID := range containerSet.Iter() {
		nnc.mu.RLock()
		containerInfo, exists := nnc.containerInfo.Load(containerID)
		nnc.mu.RUnlock()

		if exists && containerInfo.WorkloadID == workloadID && containerInfo.InstanceTemplateHash == templateHash {
			return true
		}
	}
	return false
}

// shouldSkipNeighborhoodUpdate determines if a neighborhood update should be skipped
func (nnc *NetworkNeighborhoodCache) shouldSkipNeighborhoodUpdate(workloadID string, newNeighborhood *v1beta1.NetworkNeighborhood) bool {
	existingNeighborhood, exists := nnc.workloadNeighborhoods.Load(workloadID)
	if !exists {
		return false
	}

	// Skip if existing neighborhood is complete
	if existingNeighborhood.Annotations[helpersv1.CompletionMetadataKey] == helpersv1.Complete {
		return true
	}

	// Skip if new neighborhood is not complete and we have a partial one
	return newNeighborhood.Annotations[helpersv1.CompletionMetadataKey] != helpersv1.Complete
}

// fetchFullNeighborhood retrieves the complete neighborhood from storage
func (nnc *NetworkNeighborhoodCache) fetchFullNeighborhood(ctx context.Context, neighborhood *v1beta1.NetworkNeighborhood) (*v1beta1.NetworkNeighborhood, error) {
	return nnc.storageClient.NetworkNeighborhoods(neighborhood.Namespace).Get(ctx, neighborhood.Name, metav1.GetOptions{})
}

// updateNeighborhood updates the neighborhood cache
func (nnc *NetworkNeighborhoodCache) updateNeighborhood(workloadID string, neighborhood *v1beta1.NetworkNeighborhood) {
	nnc.workloadNeighborhoods.Set(workloadID, neighborhood)

	logger.L().Debug("updated network neighborhood in cache",
		helpers.String("workloadID", workloadID),
		helpers.String("namespace", neighborhood.Namespace),
		helpers.String("status", neighborhood.Annotations[helpersv1.StatusMetadataKey]),
		helpers.String("completion", neighborhood.Annotations[helpersv1.CompletionMetadataKey]))
}

// handleUserManagedNeighborhood processes user-managed neighborhoods and merges them with base neighborhoods
func (nnc *NetworkNeighborhoodCache) handleUserManagedNeighborhood(neighborhood *v1beta1.NetworkNeighborhood) {
	normalizedName := strings.TrimPrefix(neighborhood.Name, helpersv1.UserNetworkNeighborhoodPrefix)
	uniqueIdentifier := neighborhood.ResourceVersion + string(neighborhood.UID)
	neighborhoodKey := nnc.createNeighborhoodKey(neighborhood.Namespace, normalizedName)

	// Skip if already processed this version
	if storedID, exists := nnc.userNeighborhoodIdentifiers.Load(neighborhoodKey); exists && storedID == uniqueIdentifier {
		return
	}

	// Find matching base neighborhood
	baseWorkloadID, baseNeighborhood := nnc.findMatchingBaseNeighborhood(normalizedName, neighborhood.Namespace)
	if baseNeighborhood == nil {
		return
	}

	// Fetch and merge neighborhoods
	fullUserNeighborhood, err := nnc.fetchFullNeighborhood(context.Background(), neighborhood)
	if err != nil {
		logger.L().Error("failed to get user-managed network neighborhood",
			helpers.String("namespace", neighborhood.Namespace),
			helpers.String("neighborhoodName", neighborhood.Name),
			helpers.Error(err))
		return
	}

	originalNeighborhood, err := nnc.fetchFullNeighborhood(context.Background(), baseNeighborhood)
	if err != nil {
		logger.L().Error("failed to get original network neighborhood",
			helpers.String("namespace", baseNeighborhood.Namespace),
			helpers.String("neighborhoodName", baseNeighborhood.Name),
			helpers.Error(err))
		return
	}

	mergedNeighborhood := nnc.mergeNeighborhoods(originalNeighborhood, fullUserNeighborhood)
	nnc.updateMergedNeighborhood(baseWorkloadID, mergedNeighborhood)
	nnc.userNeighborhoodIdentifiers.Set(neighborhoodKey, uniqueIdentifier)
}

// findMatchingBaseNeighborhood locates the base neighborhood for user-managed neighborhood merging
func (nnc *NetworkNeighborhoodCache) findMatchingBaseNeighborhood(neighborhoodName, namespace string) (string, *v1beta1.NetworkNeighborhood) {
	var workloadID string
	var neighborhood *v1beta1.NetworkNeighborhood

	nnc.workloadNeighborhoods.Range(func(wlid string, nn *v1beta1.NetworkNeighborhood) bool {
		if nn.Name == neighborhoodName && nn.Namespace == namespace {
			workloadID = wlid
			neighborhood = nn
			return false // Stop iteration
		}
		return true
	})

	return workloadID, neighborhood
}

// updateMergedNeighborhood updates cache with merged neighborhood and its state
func (nnc *NetworkNeighborhoodCache) updateMergedNeighborhood(workloadID string, mergedNeighborhood *v1beta1.NetworkNeighborhood) {
	nnc.workloadNeighborhoods.Set(workloadID, mergedNeighborhood)

	profileState := &objectcache.ProfileState{
		Completion: mergedNeighborhood.Annotations[helpersv1.CompletionMetadataKey],
		Status:     mergedNeighborhood.Annotations[helpersv1.StatusMetadataKey],
		Name:       mergedNeighborhood.Name,
		Error:      nil,
	}
	nnc.workloadStates.Set(workloadID, profileState)

	logger.L().Debug("merged user-managed network neighborhood with base neighborhood",
		helpers.String("workloadID", workloadID),
		helpers.String("namespace", mergedNeighborhood.Namespace))
}

// ContainerCallback handles container lifecycle events
func (nnc *NetworkNeighborhoodCache) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if nnc.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
			return
		}

		go func() {
			if err := nnc.addContainer(notif.Container); err != nil {
				logger.L().Error("failed to add container to cache", helpers.Error(err))
			}
		}()
	case containercollection.EventTypeRemoveContainer:
		if nnc.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
			return
		}

		// Run removal in goroutine to prevent blocking the event system
		// and maintain consistency with add operations
		go func() {
			containerID := notif.Container.Runtime.ContainerID
			nnc.removeContainer(containerID)
			logger.L().Debug("container removed from cache", helpers.String("containerID", containerID))
		}()
	}
}

// addContainer registers a new container in the cache
func (nnc *NetworkNeighborhoodCache) addContainer(container *containercollection.Container) error {
	containerID := container.Runtime.ContainerID
	namespace := container.K8s.Namespace

	sharedData, err := nnc.waitForSharedData(containerID)
	if err != nil {
		return fmt.Errorf("failed to get shared data for container %s: %w", containerID, err)
	}

	workloadID := sharedData.Wlid
	if workloadID == "" {
		logger.L().Debug("empty workloadID for container", helpers.String("containerID", containerID))
		return nil
	}

	containerInfo := &ContainerInfo{
		ContainerID:          containerID,
		WorkloadID:           workloadID,
		InstanceTemplateHash: sharedData.InstanceID.GetTemplateHash(),
		Namespace:            namespace,
	}

	nnc.mu.Lock()
	defer nnc.mu.Unlock()

	nnc.containerInfo.Set(containerID, containerInfo)
	nnc.addContainerToNamespace(namespace, containerID)
	nnc.ensureWorkloadStateExists(workloadID)

	logger.L().Debug("container added to cache",
		helpers.String("containerID", containerID),
		helpers.String("workloadID", workloadID),
		helpers.String("namespace", namespace))

	return nil
}

// addContainerToNamespace adds a container to the namespace mapping
func (nnc *NetworkNeighborhoodCache) addContainerToNamespace(namespace, containerID string) {
	containerSet, exists := nnc.namespaceContainers.Load(namespace)
	if !exists || containerSet == nil {
		containerSet = mapset.NewSet[string]()
		nnc.namespaceContainers.Set(namespace, containerSet)
	}
	containerSet.Add(containerID)
}

// ensureWorkloadStateExists initializes workload state if it doesn't exist
func (nnc *NetworkNeighborhoodCache) ensureWorkloadStateExists(workloadID string) {
	if _, exists := nnc.workloadStates.Load(workloadID); !exists {
		nnc.workloadStates.Set(workloadID, nil)
	}
}

// removeContainer removes a container and cleans up associated resources
func (nnc *NetworkNeighborhoodCache) removeContainer(containerID string) {
	nnc.mu.Lock()
	defer nnc.mu.Unlock()

	containerInfo, exists := nnc.containerInfo.Load(containerID)
	if !exists {
		logger.L().Debug("containerID not found in cache", helpers.String("containerID", containerID))
		return
	}

	nnc.cleanupNamespaceMapping(containerInfo)
	nnc.cleanupContainerResources(containerID)
	nnc.cleanupUnusedWorkload(containerInfo.WorkloadID)
}

// cleanupNamespaceMapping removes container from namespace mapping
func (nnc *NetworkNeighborhoodCache) cleanupNamespaceMapping(containerInfo *ContainerInfo) {
	if containerSet, exists := nnc.namespaceContainers.Load(containerInfo.Namespace); exists {
		containerSet.Remove(containerInfo.ContainerID)
		if containerSet.Cardinality() == 0 {
			nnc.namespaceContainers.Delete(containerInfo.Namespace)
		}
	}
}

// cleanupContainerResources removes container-specific resources
func (nnc *NetworkNeighborhoodCache) cleanupContainerResources(containerID string) {
	nnc.containerInfo.Delete(containerID)
}

// cleanupUnusedWorkload removes workload data if no containers are using it
func (nnc *NetworkNeighborhoodCache) cleanupUnusedWorkload(workloadID string) {
	if nnc.isWorkloadStillInUse(workloadID) {
		return
	}

	if neighborhood, exists := nnc.workloadNeighborhoods.Load(workloadID); exists {
		neighborhoodKey := nnc.createNeighborhoodKey(neighborhood.Namespace, neighborhood.Name)
		nnc.userNeighborhoodIdentifiers.Delete(neighborhoodKey)
	}

	nnc.workloadStates.Delete(workloadID)
	nnc.workloadNeighborhoods.Delete(workloadID)

	logger.L().Debug("deleted workloadID from cache", helpers.String("workloadID", workloadID))
}

// isWorkloadStillInUse checks if any container is still using the workload
func (nnc *NetworkNeighborhoodCache) isWorkloadStillInUse(workloadID string) bool {
	workloadInUse := false
	nnc.containerInfo.Range(func(_ string, info *ContainerInfo) bool {
		if info.WorkloadID == workloadID {
			workloadInUse = true
			return false // Stop iteration
		}
		return true
	})
	return workloadInUse
}

// waitForSharedData waits for shared container data with exponential backoff
func (nnc *NetworkNeighborhoodCache) waitForSharedData(containerID string) (*utils.WatchedContainerData, error) {
	return backoff.Retry(context.Background(), func() (*utils.WatchedContainerData, error) {
		if sharedData := nnc.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

// Utility methods

func (nnc *NetworkNeighborhoodCache) createNeighborhoodKey(namespace, name string) NetworkNeighborhoodKey {
	return NetworkNeighborhoodKey(fmt.Sprintf("%s/%s", namespace, name))
}

func (nnc *NetworkNeighborhoodCache) isUserManagedNeighborhood(neighborhood *v1beta1.NetworkNeighborhood) bool {
	return neighborhood.Annotations != nil &&
		neighborhood.Annotations[helpersv1.ManagedByMetadataKey] == helpersv1.ManagedByUserValue &&
		strings.HasPrefix(neighborhood.GetName(), helpersv1.UserNetworkNeighborhoodPrefix)
}

// mergeNeighborhoods combines a base neighborhood with a user-managed neighborhood
func (nnc *NetworkNeighborhoodCache) mergeNeighborhoods(base, userManaged *v1beta1.NetworkNeighborhood) *v1beta1.NetworkNeighborhood {
	merged := base.DeepCopy()

	// Merge container specifications
	merged.Spec.Containers = nnc.mergeContainerSpecs(merged.Spec.Containers, userManaged.Spec.Containers)
	merged.Spec.InitContainers = nnc.mergeContainerSpecs(merged.Spec.InitContainers, userManaged.Spec.InitContainers)
	merged.Spec.EphemeralContainers = nnc.mergeContainerSpecs(merged.Spec.EphemeralContainers, userManaged.Spec.EphemeralContainers)

	// Merge label selectors
	nnc.mergeLabelSelector(&merged.Spec.LabelSelector, &userManaged.Spec.LabelSelector)

	return merged
}

// mergeContainerSpecs merges container specifications
func (nnc *NetworkNeighborhoodCache) mergeContainerSpecs(base, userManaged []v1beta1.NetworkNeighborhoodContainer) []v1beta1.NetworkNeighborhoodContainer {
	if len(userManaged) != len(base) {
		logger.L().Warning("failed to merge user-managed network neighborhood with base neighborhood",
			helpers.Int("baseContainers", len(base)),
			helpers.Int("userManagedContainers", len(userManaged)),
			helpers.String("reason", "container count mismatch"))
		return base
	}

	for i := range base {
		for j := range userManaged {
			if base[i].Name == userManaged[j].Name {
				nnc.mergeContainerData(&base[i], &userManaged[j])
				break
			}
		}
	}
	return base
}

// mergeContainerData merges individual container network data
func (nnc *NetworkNeighborhoodCache) mergeContainerData(base, userManaged *v1beta1.NetworkNeighborhoodContainer) {
	base.Ingress = nnc.mergeNetworkNeighbors(base.Ingress, userManaged.Ingress)
	base.Egress = nnc.mergeNetworkNeighbors(base.Egress, userManaged.Egress)
}

// mergeNetworkNeighbors merges network neighbor lists
func (nnc *NetworkNeighborhoodCache) mergeNetworkNeighbors(base, userManaged []v1beta1.NetworkNeighbor) []v1beta1.NetworkNeighbor {
	neighborMap := make(map[string]int)
	for i, neighbor := range base {
		neighborMap[neighbor.Identifier] = i
	}

	for _, userNeighbor := range userManaged {
		if idx, exists := neighborMap[userNeighbor.Identifier]; exists {
			base[idx] = nnc.mergeNetworkNeighbor(base[idx], userNeighbor)
		} else {
			base = append(base, userNeighbor)
		}
	}

	return base
}

// mergeNetworkNeighbor merges individual network neighbors
func (nnc *NetworkNeighborhoodCache) mergeNetworkNeighbor(base, userManaged v1beta1.NetworkNeighbor) v1beta1.NetworkNeighbor {
	merged := base.DeepCopy()

	// Merge DNS names (removing duplicates)
	dnsSet := make(map[string]struct{})
	for _, dns := range base.DNSNames {
		dnsSet[dns] = struct{}{}
	}
	for _, dns := range userManaged.DNSNames {
		dnsSet[dns] = struct{}{}
	}

	merged.DNSNames = make([]string, 0, len(dnsSet))
	for dns := range dnsSet {
		merged.DNSNames = append(merged.DNSNames, dns)
	}

	// Merge ports
	merged.Ports = nnc.mergeNetworkPorts(merged.Ports, userManaged.Ports)

	// Merge selectors
	if userManaged.PodSelector != nil {
		if merged.PodSelector == nil {
			merged.PodSelector = &metav1.LabelSelector{}
		}
		nnc.mergeLabelSelector(merged.PodSelector, userManaged.PodSelector)
	}

	if userManaged.NamespaceSelector != nil {
		if merged.NamespaceSelector == nil {
			merged.NamespaceSelector = &metav1.LabelSelector{}
		}
		nnc.mergeLabelSelector(merged.NamespaceSelector, userManaged.NamespaceSelector)
	}

	// Override with user-managed values if provided
	if userManaged.IPAddress != "" {
		merged.IPAddress = userManaged.IPAddress
	}
	if userManaged.Type != "" {
		merged.Type = userManaged.Type
	}

	return *merged
}

// mergeNetworkPorts merges network port lists
func (nnc *NetworkNeighborhoodCache) mergeNetworkPorts(base, userManaged []v1beta1.NetworkPort) []v1beta1.NetworkPort {
	portMap := make(map[string]int)
	for i, port := range base {
		portMap[port.Name] = i
	}

	for _, userPort := range userManaged {
		if idx, exists := portMap[userPort.Name]; exists {
			base[idx] = userPort
		} else {
			base = append(base, userPort)
		}
	}

	return base
}

// mergeLabelSelector merges label selectors
func (nnc *NetworkNeighborhoodCache) mergeLabelSelector(base, userManaged *metav1.LabelSelector) {
	if userManaged.MatchLabels != nil {
		if base.MatchLabels == nil {
			base.MatchLabels = make(map[string]string)
		}
		for k, v := range userManaged.MatchLabels {
			base.MatchLabels[k] = v
		}
	}

	base.MatchExpressions = append(base.MatchExpressions, userManaged.MatchExpressions...)
}

// Public API methods

// GetNetworkNeighborhood retrieves the network neighborhood for a container
func (nnc *NetworkNeighborhoodCache) GetNetworkNeighborhood(containerID string) *v1beta1.NetworkNeighborhood {
	containerInfo, exists := nnc.containerInfo.Load(containerID)
	if !exists || containerInfo.WorkloadID == "" {
		return nil
	}

	if neighborhood, exists := nnc.workloadNeighborhoods.Load(containerInfo.WorkloadID); exists {
		return neighborhood
	}
	return nil
}

// GetNetworkNeighborhoodState retrieves the profile state for a container
func (nnc *NetworkNeighborhoodCache) GetNetworkNeighborhoodState(containerID string) *objectcache.ProfileState {
	containerInfo, exists := nnc.containerInfo.Load(containerID)
	if !exists {
		return &objectcache.ProfileState{
			Error: fmt.Errorf("container %s not found in cache", containerID),
		}
	}

	if containerInfo.WorkloadID == "" {
		return &objectcache.ProfileState{
			Error: fmt.Errorf("no workload ID for container %s", containerID),
		}
	}

	if profileState, exists := nnc.workloadStates.Load(containerInfo.WorkloadID); exists {
		if profileState != nil {
			return profileState
		}
		return &objectcache.ProfileState{
			Error: fmt.Errorf("profile state not available"),
		}
	}

	return &objectcache.ProfileState{
		Error: fmt.Errorf("profile state not found for workload ID %s", containerInfo.WorkloadID),
	}
}

// Ensure NetworkNeighborhoodCache implements the required interface
var _ objectcache.NetworkNeighborhoodCache = (*NetworkNeighborhoodCache)(nil)
