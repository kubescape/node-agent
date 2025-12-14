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
	"github.com/kubescape/node-agent/pkg/resourcelocks"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	versioned "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContainerInfo holds container metadata we need for network neighborhood mapping
type ContainerInfo struct {
	ContainerID          string
	WorkloadID           string
	InstanceTemplateHash string
	Namespace            string
	SeenFromStart        bool // True if container was seen from the start
}

// NetworkNeighborhoodCacheImpl implements the NetworkNeighborhoodCache interface
type NetworkNeighborhoodCacheImpl struct {
	cfg                                        config.Config
	workloadIDToNetworkNeighborhood            maps.SafeMap[string, *v1beta1.NetworkNeighborhood]
	workloadIDToProfileState                   maps.SafeMap[string, *objectcache.ProfileState] // Tracks profile state even if not in cache
	containerIDToInfo                          maps.SafeMap[string, *ContainerInfo]
	networkNeighborhoodToUserManagedIdentifier maps.SafeMap[string, string] // networkNeighborhoodName -> user-managed profile unique identifier
	storageClient                              versioned.SpdxV1beta1Interface
	k8sObjectCache                             objectcache.K8sObjectCache
	updateInterval                             time.Duration
	updateInProgress                           bool                         // Flag to track if update is in progress
	updateMutex                                sync.Mutex                   // Mutex to protect the flag
	containerLocks                             *resourcelocks.ResourceLocks // Locks for each container to prevent concurrent modifications
}

// NewNetworkNeighborhoodCache creates a new network neighborhood cache with periodic updates
func NewNetworkNeighborhoodCache(cfg config.Config, storageClient versioned.SpdxV1beta1Interface, k8sObjectCache objectcache.K8sObjectCache) *NetworkNeighborhoodCacheImpl {
	updateInterval := utils.AddJitter(cfg.ProfilesCacheRefreshRate, 10) // Add 10% jitter to avoid high load on the storage

	nnc := &NetworkNeighborhoodCacheImpl{
		cfg:                             cfg,
		workloadIDToNetworkNeighborhood: maps.SafeMap[string, *v1beta1.NetworkNeighborhood]{},
		workloadIDToProfileState:        maps.SafeMap[string, *objectcache.ProfileState]{},
		containerIDToInfo:               maps.SafeMap[string, *ContainerInfo]{},
		networkNeighborhoodToUserManagedIdentifier: maps.SafeMap[string, string]{},
		storageClient:  storageClient,
		k8sObjectCache: k8sObjectCache,
		updateInterval: updateInterval,
		containerLocks: resourcelocks.New(),
	}

	return nnc
}

// Start begins the periodic update process
func (nnc *NetworkNeighborhoodCacheImpl) Start(ctx context.Context) {
	go nnc.periodicUpdate(ctx)
}

// periodicUpdate periodically fetches and updates network neighborhoods from storage
func (nnc *NetworkNeighborhoodCacheImpl) periodicUpdate(ctx context.Context) {
	ticker := time.NewTicker(nnc.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if an update is already in progress
			nnc.updateMutex.Lock()
			if nnc.updateInProgress {
				// Skip this update cycle
				logger.L().Debug("skipping profile update: previous update still in progress")
				nnc.updateMutex.Unlock()
				continue
			}

			// Set the flag and release the lock before the potentially long-running call
			nnc.updateInProgress = true
			nnc.updateMutex.Unlock()

			// Run the update directly
			nnc.updateAllNetworkNeighborhoods(ctx)

			// Mark the update as complete
			nnc.updateMutex.Lock()
			nnc.updateInProgress = false
			nnc.updateMutex.Unlock()

		case <-ctx.Done():
			logger.L().Info("NetworkNeighborhoodsCache periodic update stopped")
			return
		}
	}
}

// updateAllNetworkNeighborhoods fetches all network neighborhoods from storage and updates the cache
func (nnc *NetworkNeighborhoodCacheImpl) updateAllNetworkNeighborhoods(ctx context.Context) {
	// Get unique namespaces from container info
	namespaces := nnc.getNamespaces()
	if len(namespaces) == 0 {
		logger.L().Debug("no namespaces found in cache, skipping network neighborhood update")
		return
	}

	// Iterate over each namespace
	for _, namespace := range namespaces {
		// Get container IDs for this namespace
		containerIDs := nnc.getContainerIDsForNamespace(namespace)
		if len(containerIDs) == 0 {
			logger.L().Debug("no containers found for namespace, skipping",
				helpers.String("namespace", namespace))
			continue
		}

		// Get network neighborhoods list for this namespace
		nnList, err := nnc.storageClient.NetworkNeighborhoods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.L().Error("failed to list network neighborhoods",
				helpers.String("namespace", namespace),
				helpers.Error(err))
			continue
		}

		// Process each network neighborhood
		for _, nn := range nnList.Items {
			// Handle user-managed network neighborhoods
			if isUserManagedNN(&nn) {
				nnc.handleUserManagedNetworkNeighborhood(&nn)
				continue
			}

			// Get the workload ID from network neighborhood
			workloadID := nnc.wlidKey(
				nn.Annotations[helpersv1.WlidMetadataKey],
				nn.Labels[helpersv1.TemplateHashKey],
			)
			if workloadID == "" {
				continue
			}

			// Update profile state regardless of whether we'll update the full profile
			profileState := &objectcache.ProfileState{
				Completion: nn.Annotations[helpersv1.CompletionMetadataKey],
				Status:     nn.Annotations[helpersv1.StatusMetadataKey],
				Name:       nn.Name,
				Error:      nil,
			}
			nnc.workloadIDToProfileState.Set(workloadID, profileState)

			// Only consider completed network neighborhoods
			if nn.Annotations[helpersv1.StatusMetadataKey] != helpersv1.Completed {
				continue
			}

			// Check if this workload ID is used by any container in this namespace
			workloadIDInUse := false
			hasNewContainer := false // Track if any container using this workload was seen from start
			for _, containerID := range containerIDs {
				if containerInfo, exists := nnc.containerIDToInfo.Load(containerID); exists &&
					containerInfo.WorkloadID == workloadID &&
					containerInfo.InstanceTemplateHash == nn.Labels[helpersv1.TemplateHashKey] {
					workloadIDInUse = true
					// If any container was seen from start, mark it
					if containerInfo.SeenFromStart {
						hasNewContainer = true
					}
				}
			}

			if !workloadIDInUse {
				continue
			}

			// If we have a "new" container (seen from start) and the network neighborhood is partial,
			// skip it - we don't want to use partial profiles for containers we're tracking from the start
			if hasNewContainer && nn.Annotations[helpersv1.CompletionMetadataKey] == helpersv1.Partial {
				logger.L().Debug("skipping partial network neighborhood for container seen from start",
					helpers.String("workloadID", workloadID),
					helpers.String("namespace", namespace))
				continue
			}

			// Update the network neighborhood in the cache
			if existingNN, exists := nnc.workloadIDToNetworkNeighborhood.Load(workloadID); exists {
				// If the network neighborhood already exists and it's complete/completed, continue to the next one
				if existingNN.Annotations[helpersv1.CompletionMetadataKey] == helpersv1.Full {
					continue
				}

				// If the new network neighborhood is not complete and we already have a completed/partial one, skip it
				if nn.Annotations[helpersv1.CompletionMetadataKey] != helpersv1.Full {
					continue
				}
			}

			// Fetch the network neighborhood from storage
			fullNN, err := nnc.storageClient.NetworkNeighborhoods(namespace).Get(ctx, nn.Name, metav1.GetOptions{})
			if err != nil {
				logger.L().Error("failed to get network neighborhood",
					helpers.String("workloadID", workloadID),
					helpers.String("namespace", namespace),
					helpers.Error(err))
				profileState.Error = err
				nnc.workloadIDToProfileState.Set(workloadID, profileState)
				continue
			}

			nnc.workloadIDToNetworkNeighborhood.Set(workloadID, fullNN)
			logger.L().Debug("updated network neighborhood in cache",
				helpers.String("workloadID", workloadID),
				helpers.String("namespace", namespace),
				helpers.String("status", nn.Annotations[helpersv1.StatusMetadataKey]),
				helpers.String("completion", nn.Annotations[helpersv1.CompletionMetadataKey]))
		}
	}
}

// handleUserManagedNetworkNeighborhood handles user-managed network neighborhoods
func (nnc *NetworkNeighborhoodCacheImpl) handleUserManagedNetworkNeighborhood(nn *v1beta1.NetworkNeighborhood) {
	normalizedNNName := strings.TrimPrefix(nn.Name, helpersv1.UserNetworkNeighborhoodPrefix)
	userManagedNNUniqueIdentifier := nn.ResourceVersion + string(nn.UID)

	// Create a unique tracking key for this user network neighborhood
	nnKey := nnc.networkNeighborhoodKey(nn.Namespace, normalizedNNName)

	// Check if we've already processed this exact version of the user-managed network neighborhood
	if storedIdentifier, exists := nnc.networkNeighborhoodToUserManagedIdentifier.Load(nnKey); exists &&
		storedIdentifier == userManagedNNUniqueIdentifier {
		return
	}

	// Find and collect the network neighborhood to merge
	var toMerge struct {
		wlid string
		nn   *v1beta1.NetworkNeighborhood
	}

	nnc.workloadIDToNetworkNeighborhood.Range(func(wlid string, originalNN *v1beta1.NetworkNeighborhood) bool {
		if originalNN.Name == normalizedNNName && originalNN.Namespace == nn.Namespace {
			toMerge.wlid = wlid
			toMerge.nn = originalNN
			logger.L().Debug("found matching network neighborhood for user-managed network neighborhood",
				helpers.String("workloadID", wlid),
				helpers.String("namespace", originalNN.Namespace),
				helpers.String("nnName", originalNN.Name))
			// Stop iteration
			return false
		}
		return true
	})

	// If we didn't find a matching network neighborhood, skip merging
	if toMerge.nn == nil {
		return
	}

	// Fetch the full user network neighborhood
	fullUserNN, err := nnc.storageClient.NetworkNeighborhoods(nn.Namespace).Get(
		context.Background(), nn.Name, metav1.GetOptions{})
	if err != nil {
		logger.L().Error("failed to get user-managed network neighborhood",
			helpers.String("namespace", nn.Namespace),
			helpers.String("nnName", nn.Name),
			helpers.Error(err))
		return
	}

	// Merge the user-managed network neighborhood with the normal network neighborhood

	// First, pull the original network neighborhood from the storage
	originalNN, err := nnc.storageClient.NetworkNeighborhoods(toMerge.nn.Namespace).Get(
		context.Background(), toMerge.nn.Name, metav1.GetOptions{})
	if err != nil {
		logger.L().Error("failed to get original network neighborhood",
			helpers.String("namespace", toMerge.nn.Namespace),
			helpers.String("nnName", toMerge.nn.Name),
			helpers.Error(err))
		return
	}
	// Merge the network neighborhoods
	mergedNN := nnc.performMerge(originalNN, fullUserNN)
	// Update the cache with the merged network neighborhood
	nnc.workloadIDToNetworkNeighborhood.Set(toMerge.wlid, mergedNN)
	// Update profile state for the merged profile
	profileState := &objectcache.ProfileState{
		Completion: mergedNN.Annotations[helpersv1.CompletionMetadataKey],
		Status:     mergedNN.Annotations[helpersv1.StatusMetadataKey],
		Name:       mergedNN.Name,
		Error:      nil,
	}
	nnc.workloadIDToProfileState.Set(toMerge.wlid, profileState)
	logger.L().Debug("merged user-managed network neighborhood with normal network neighborhood",
		helpers.String("workloadID", toMerge.wlid),
		helpers.String("namespace", nn.Namespace),
		helpers.String("nnName", nn.Name))

	// Record that we've processed this version of the network neighborhood
	nnc.networkNeighborhoodToUserManagedIdentifier.Set(nnKey, userManagedNNUniqueIdentifier)
}

// ContainerCallback handles container lifecycle events
func (nnc *NetworkNeighborhoodCacheImpl) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if nnc.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
			return
		}
		go nnc.addContainerWithTimeout(notif.Container)
	case containercollection.EventTypeRemoveContainer:
		if nnc.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
			return
		}
		go nnc.deleteContainer(notif.Container.Runtime.ContainerID)
	}
}

// addContainerWithTimeout handles adding a container with a timeout to prevent hanging
func (nnc *NetworkNeighborhoodCacheImpl) addContainerWithTimeout(container *containercollection.Container) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- nnc.addContainer(container, ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			logger.L().Error("failed to add container to the cache", helpers.Error(err))
		}
	case <-ctx.Done():
		logger.L().Error("timeout while adding container to the cache",
			helpers.String("containerID", container.Runtime.ContainerID),
			helpers.String("containerName", container.Runtime.ContainerName),
			helpers.String("podName", container.K8s.PodName),
			helpers.String("namespace", container.K8s.Namespace))
	}
}

// addContainer adds a container to the cache
func (nnc *NetworkNeighborhoodCacheImpl) addContainer(container *containercollection.Container, ctx context.Context) error {
	containerID := container.Runtime.ContainerID

	return nnc.containerLocks.WithLockAndError(containerID, func() error {
		// Get workload ID from shared data
		sharedData, err := nnc.waitForSharedContainerData(containerID, ctx)
		if err != nil {
			logger.L().Error("failed to get shared data for container",
				helpers.String("containerID", containerID),
				helpers.Error(err))
			return err
		}

		workloadID := nnc.wlidKey(sharedData.Wlid, sharedData.InstanceID.GetTemplateHash())
		if workloadID == "" {
			logger.L().Debug("empty workloadID for container", helpers.String("containerID", containerID))
			return nil
		}

		// If container restarts and profile is partial, delete it from cache
		// This ensures we don't alert on activity we didn't see after restart
		if existingNN, exists := nnc.workloadIDToNetworkNeighborhood.Load(workloadID); exists && sharedData.GetCompletionStatus() == objectcache.WatchedContainerCompletionStatusFull {
			if existingNN != nil && existingNN.Annotations != nil {
				completion := existingNN.Annotations[helpersv1.CompletionMetadataKey]
				if completion == helpersv1.Partial {
					logger.L().Debug("deleting partial network neighborhood on container restart",
						helpers.String("containerID", containerID),
						helpers.String("workloadID", workloadID),
						helpers.String("namespace", container.K8s.Namespace))

					// Delete the network neighborhood from cache
					nnKey := nnc.networkNeighborhoodKey(existingNN.Namespace, existingNN.Name)
					nnc.networkNeighborhoodToUserManagedIdentifier.Delete(nnKey)
					nnc.workloadIDToNetworkNeighborhood.Delete(workloadID)
				}
			}
		}

		// Create container info
		// Mark container as "seen from start" if it has full completion status
		seenFromStart := sharedData.GetCompletionStatus() == objectcache.WatchedContainerCompletionStatusFull
		containerInfo := &ContainerInfo{
			ContainerID:          containerID,
			WorkloadID:           workloadID,
			InstanceTemplateHash: sharedData.InstanceID.GetTemplateHash(),
			Namespace:            container.K8s.Namespace,
			SeenFromStart:        seenFromStart,
		}

		// Add to container info map
		nnc.containerIDToInfo.Set(containerID, containerInfo)

		// Create workload ID to state mapping
		if _, exists := nnc.workloadIDToProfileState.Load(workloadID); !exists {
			nnc.workloadIDToProfileState.Set(workloadID, nil)
		}

		logger.L().Debug("container added to cache",
			helpers.String("containerID", containerID),
			helpers.String("workloadID", workloadID),
			helpers.String("namespace", container.K8s.Namespace))

		return nil
	})
}

// deleteContainer deletes a container from the cache
func (nnc *NetworkNeighborhoodCacheImpl) deleteContainer(containerID string) {
	nnc.containerLocks.WithLock(containerID, func() {
		// Get container info
		containerInfo, exists := nnc.containerIDToInfo.Load(containerID)
		if !exists {
			logger.L().Debug("containerID not found in cache", helpers.String("containerID", containerID))
			return
		}

		// Clean up container info
		nnc.containerIDToInfo.Delete(containerID)

		// Check if any other container is using the same workload ID
		workloadStillInUse := false
		nnc.containerIDToInfo.Range(func(_ string, info *ContainerInfo) bool {
			if info.WorkloadID == containerInfo.WorkloadID {
				workloadStillInUse = true
				return false // Stop iteration
			}
			return true // Continue iteration
		})

		// If no other container is using the same workload ID, delete it from the cache
		if !workloadStillInUse {
			if nn, exists := nnc.workloadIDToNetworkNeighborhood.Load(containerInfo.WorkloadID); exists {
				// Remove any user managed identifiers related to this network neighborhood
				nnKey := nnc.networkNeighborhoodKey(nn.Namespace, nn.Name)
				nnc.networkNeighborhoodToUserManagedIdentifier.Delete(nnKey)
			}
			nnc.workloadIDToNetworkNeighborhood.Delete(containerInfo.WorkloadID)
			nnc.workloadIDToProfileState.Delete(containerInfo.WorkloadID)
			logger.L().Debug("deleted workloadID from cache", helpers.String("workloadID", containerInfo.WorkloadID))
		}
	})

	// Clean up the lock when done - call this outside the WithLock closure
	nnc.containerLocks.ReleaseLock(containerID)
}

// waitForSharedContainerData waits for shared container data to be available
func (nnc *NetworkNeighborhoodCacheImpl) waitForSharedContainerData(containerID string, ctx context.Context) (*objectcache.WatchedContainerData, error) {
	return backoff.Retry(ctx, func() (*objectcache.WatchedContainerData, error) {
		if sharedData := nnc.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

func (nnc *NetworkNeighborhoodCacheImpl) networkNeighborhoodKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func (nnc *NetworkNeighborhoodCacheImpl) wlidKey(wlid, templateHash string) string {
	return fmt.Sprintf("%s/%s", wlid, templateHash)
}

// GetNetworkNeighborhood gets the network neighborhood for a container
func (nnc *NetworkNeighborhoodCacheImpl) GetNetworkNeighborhood(containerID string) *v1beta1.NetworkNeighborhood {
	// Get container info
	if containerInfo, exists := nnc.containerIDToInfo.Load(containerID); exists {
		workloadID := containerInfo.WorkloadID
		if workloadID == "" {
			return nil
		}

		// Try to get network neighborhood from cache
		if nn, exists := nnc.workloadIDToNetworkNeighborhood.Load(workloadID); exists {
			if nn != nil {
				return nn
			}
		}
	}

	return nil
}

// GetNetworkNeighborhoodState gets the profile state for a container
func (nnc *NetworkNeighborhoodCacheImpl) GetNetworkNeighborhoodState(containerID string) *objectcache.ProfileState {
	// Get container info
	containerInfo, exists := nnc.containerIDToInfo.Load(containerID)
	if !exists {
		return &objectcache.ProfileState{
			Error: fmt.Errorf("container %s not found in cache", containerID),
		}
	}

	workloadID := containerInfo.WorkloadID
	if workloadID == "" {
		return &objectcache.ProfileState{
			Error: fmt.Errorf("no workload ID for container %s", containerID),
		}
	}

	// Try to get profile state from cache
	if profileState, exists := nnc.workloadIDToProfileState.Load(workloadID); exists {
		if profileState != nil {
			return profileState
		} else {
			return &objectcache.ProfileState{
				Error: fmt.Errorf("profile state not available - shouldn't happen"),
			}
		}
	}

	return &objectcache.ProfileState{
		Error: fmt.Errorf("profile state not found for workload ID %s", workloadID),
	}
}

// performMerge merges a user-managed network neighborhood with a normal network neighborhood
func (nnc *NetworkNeighborhoodCacheImpl) performMerge(normalNN, userManagedNN *v1beta1.NetworkNeighborhood) *v1beta1.NetworkNeighborhood {
	mergedNN := normalNN.DeepCopy()

	// Merge spec
	mergedNN.Spec.Containers = nnc.mergeContainers(mergedNN.Spec.Containers, userManagedNN.Spec.Containers)
	mergedNN.Spec.InitContainers = nnc.mergeContainers(mergedNN.Spec.InitContainers, userManagedNN.Spec.InitContainers)
	mergedNN.Spec.EphemeralContainers = nnc.mergeContainers(mergedNN.Spec.EphemeralContainers, userManagedNN.Spec.EphemeralContainers)

	// Merge LabelSelector
	if userManagedNN.Spec.LabelSelector.MatchLabels != nil {
		if mergedNN.Spec.LabelSelector.MatchLabels == nil {
			mergedNN.Spec.LabelSelector.MatchLabels = make(map[string]string)
		}
		for k, v := range userManagedNN.Spec.LabelSelector.MatchLabels {
			mergedNN.Spec.LabelSelector.MatchLabels[k] = v
		}
	}
	mergedNN.Spec.LabelSelector.MatchExpressions = append(
		mergedNN.Spec.LabelSelector.MatchExpressions,
		userManagedNN.Spec.LabelSelector.MatchExpressions...,
	)

	return mergedNN
}

func (nnc *NetworkNeighborhoodCacheImpl) mergeContainers(normalContainers, userManagedContainers []v1beta1.NetworkNeighborhoodContainer) []v1beta1.NetworkNeighborhoodContainer {
	if len(userManagedContainers) != len(normalContainers) {
		// If the number of containers don't match, we can't merge
		logger.L().Warning("NetworkNeighborhoodCacheImpl - failed to merge user-managed profile with base profile",
			helpers.Int("normalContainers len", len(normalContainers)),
			helpers.Int("userManagedContainers len", len(userManagedContainers)),
			helpers.String("reason", "number of containers don't match"))
		return normalContainers
	}

	// Assuming the normalContainers are already in the correct Pod order
	// We'll merge user containers at their corresponding positions
	for i := range normalContainers {
		for _, userContainer := range userManagedContainers {
			if normalContainers[i].Name == userContainer.Name {
				nnc.mergeContainer(&normalContainers[i], &userContainer)
				break
			}
		}
	}
	return normalContainers
}

func (nnc *NetworkNeighborhoodCacheImpl) mergeContainer(normalContainer, userContainer *v1beta1.NetworkNeighborhoodContainer) {
	// Merge ingress rules
	normalContainer.Ingress = nnc.mergeNetworkNeighbors(normalContainer.Ingress, userContainer.Ingress)

	// Merge egress rules
	normalContainer.Egress = nnc.mergeNetworkNeighbors(normalContainer.Egress, userContainer.Egress)
}

func (nnc *NetworkNeighborhoodCacheImpl) mergeNetworkNeighbors(normalNeighbors, userNeighbors []v1beta1.NetworkNeighbor) []v1beta1.NetworkNeighbor {
	// Use map to track existing neighbors by identifier
	neighborMap := make(map[string]int)
	for i, neighbor := range normalNeighbors {
		neighborMap[neighbor.Identifier] = i
	}

	// Merge or append user neighbors
	for _, userNeighbor := range userNeighbors {
		if idx, exists := neighborMap[userNeighbor.Identifier]; exists {
			// Merge existing neighbor
			normalNeighbors[idx] = nnc.mergeNetworkNeighbor(normalNeighbors[idx], userNeighbor)
		} else {
			// Append new neighbor
			normalNeighbors = append(normalNeighbors, userNeighbor)
		}
	}

	return normalNeighbors
}

func (nnc *NetworkNeighborhoodCacheImpl) mergeNetworkNeighbor(normal, user v1beta1.NetworkNeighbor) v1beta1.NetworkNeighbor {
	merged := normal.DeepCopy()

	// Merge DNS names (removing duplicates)
	dnsNamesSet := make(map[string]struct{})
	for _, dns := range normal.DNSNames {
		dnsNamesSet[dns] = struct{}{}
	}
	for _, dns := range user.DNSNames {
		dnsNamesSet[dns] = struct{}{}
	}
	merged.DNSNames = make([]string, 0, len(dnsNamesSet))
	for dns := range dnsNamesSet {
		merged.DNSNames = append(merged.DNSNames, dns)
	}

	// Merge ports based on patchMergeKey (name)
	merged.Ports = nnc.mergeNetworkPorts(merged.Ports, user.Ports)

	// Merge pod selector if provided
	if user.PodSelector != nil {
		if merged.PodSelector == nil {
			merged.PodSelector = &metav1.LabelSelector{}
		}
		if user.PodSelector.MatchLabels != nil {
			if merged.PodSelector.MatchLabels == nil {
				merged.PodSelector.MatchLabels = make(map[string]string)
			}
			for k, v := range user.PodSelector.MatchLabels {
				merged.PodSelector.MatchLabels[k] = v
			}
		}
		merged.PodSelector.MatchExpressions = append(
			merged.PodSelector.MatchExpressions,
			user.PodSelector.MatchExpressions...,
		)
	}

	// Merge namespace selector if provided
	if user.NamespaceSelector != nil {
		if merged.NamespaceSelector == nil {
			merged.NamespaceSelector = &metav1.LabelSelector{}
		}
		if user.NamespaceSelector.MatchLabels != nil {
			if merged.NamespaceSelector.MatchLabels == nil {
				merged.NamespaceSelector.MatchLabels = make(map[string]string)
			}
			for k, v := range user.NamespaceSelector.MatchLabels {
				merged.NamespaceSelector.MatchLabels[k] = v
			}
		}
		merged.NamespaceSelector.MatchExpressions = append(
			merged.NamespaceSelector.MatchExpressions,
			user.NamespaceSelector.MatchExpressions...,
		)
	}

	// Take the user's IP address if provided
	if user.IPAddress != "" {
		merged.IPAddress = user.IPAddress
	}

	// Take the user's type if provided
	if user.Type != "" {
		merged.Type = user.Type
	}

	return *merged
}

func (nnc *NetworkNeighborhoodCacheImpl) mergeNetworkPorts(normalPorts, userPorts []v1beta1.NetworkPort) []v1beta1.NetworkPort {
	// Use map to track existing ports by name (patchMergeKey)
	portMap := make(map[string]int)
	for i, port := range normalPorts {
		portMap[port.Name] = i
	}

	// Merge or append user ports
	for _, userPort := range userPorts {
		if idx, exists := portMap[userPort.Name]; exists {
			// Update existing port
			normalPorts[idx] = userPort
		} else {
			// Append new port
			normalPorts = append(normalPorts, userPort)
		}
	}

	return normalPorts
}

func isUserManagedNN(nn *v1beta1.NetworkNeighborhood) bool {
	return nn.Annotations != nil &&
		nn.Annotations[helpersv1.ManagedByMetadataKey] == helpersv1.ManagedByUserValue &&
		strings.HasPrefix(nn.GetName(), helpersv1.UserNetworkNeighborhoodPrefix)
}

// getNamespaces retrieves all unique namespaces from the container info cache
func (nnc *NetworkNeighborhoodCacheImpl) getNamespaces() []string {
	namespaceSet := mapset.NewSet[string]()
	nnc.containerIDToInfo.Range(func(_ string, info *ContainerInfo) bool {
		namespaceSet.Add(info.Namespace)
		return true
	})
	return namespaceSet.ToSlice()
}

// getContainerIDsForNamespace retrieves all container IDs for a given namespace
func (nnc *NetworkNeighborhoodCacheImpl) getContainerIDsForNamespace(namespace string) []string {
	containerIDs := []string{}
	nnc.containerIDToInfo.Range(func(containerID string, info *ContainerInfo) bool {
		if info.Namespace == namespace {
			containerIDs = append(containerIDs, containerID)
		}
		return true
	})
	return containerIDs
}

// Ensure NetworkNeighborhoodCacheImpl implements the NetworkNeighborhoodCache interface
var _ objectcache.NetworkNeighborhoodCache = (*NetworkNeighborhoodCacheImpl)(nil)
