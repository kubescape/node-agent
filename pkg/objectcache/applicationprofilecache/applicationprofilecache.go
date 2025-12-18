package applicationprofilecache

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
	"github.com/kubescape/node-agent/pkg/objectcache/applicationprofilecache/callstackcache"
	"github.com/kubescape/node-agent/pkg/resourcelocks"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	versioned "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContainerInfo holds container metadata we need for application profile mapping
type ContainerInfo struct {
	ContainerID               string
	WorkloadID                string
	InstanceTemplateHash      string
	Namespace                 string
	Name                      string
	SeenContainerFromTheStart bool // True if container was seen from the start
	UserDefinedProfile   string
}

// ContainerCallStackIndex maintains call stack search trees for a container
type ContainerCallStackIndex struct {
	searchTree *callstackcache.CallStackSearchTree
}

type ApplicationProfileCacheImpl struct {
	cfg                            config.Config
	workloadIDToProfile            maps.SafeMap[string, *v1beta1.ApplicationProfile]
	workloadIDToProfileState       maps.SafeMap[string, *objectcache.ProfileState] // Tracks profile state even if not in cache
	containerIDToInfo              maps.SafeMap[string, *ContainerInfo]
	profileToUserManagedIdentifier maps.SafeMap[string, string] // profileName -> user-managed profile unique identifier (This is used to prevent merging the same user-managed profile multiple times)
	containerToCallStackIndex      maps.SafeMap[string, *ContainerCallStackIndex]
	storageClient                  versioned.SpdxV1beta1Interface
	k8sObjectCache                 objectcache.K8sObjectCache
	updateInterval                 time.Duration
	updateInProgress               bool                         // Flag to track if update is in progress
	updateMutex                    sync.Mutex                   // Mutex to protect the flag
	containerLocks                 *resourcelocks.ResourceLocks // Locks for each container to prevent concurrent modifications
}

// NewApplicationProfileCache creates a new application profile cache with periodic updates
func NewApplicationProfileCache(cfg config.Config, storageClient versioned.SpdxV1beta1Interface, k8sObjectCache objectcache.K8sObjectCache) *ApplicationProfileCacheImpl {
	updateInterval := utils.AddJitter(cfg.ProfilesCacheRefreshRate, 10) // Add 10% jitter to avoid high load on the storage

	apc := &ApplicationProfileCacheImpl{
		cfg:                            cfg,
		workloadIDToProfile:            maps.SafeMap[string, *v1beta1.ApplicationProfile]{},
		workloadIDToProfileState:       maps.SafeMap[string, *objectcache.ProfileState]{},
		containerIDToInfo:              maps.SafeMap[string, *ContainerInfo]{},
		profileToUserManagedIdentifier: maps.SafeMap[string, string]{},
		containerToCallStackIndex:      maps.SafeMap[string, *ContainerCallStackIndex]{},
		storageClient:                  storageClient,
		k8sObjectCache:                 k8sObjectCache,
		updateInterval:                 updateInterval,
		containerLocks:                 resourcelocks.New(),
	}

	return apc
}

// Start begins the periodic update process
func (apc *ApplicationProfileCacheImpl) Start(ctx context.Context) {
	go apc.periodicUpdate(ctx)
}

// periodicUpdate periodically fetches and updates application profiles from storage
func (apc *ApplicationProfileCacheImpl) periodicUpdate(ctx context.Context) {
	ticker := time.NewTicker(apc.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if an update is already in progress
			apc.updateMutex.Lock()
			if apc.updateInProgress {
				// Skip this update cycle
				logger.L().Debug("skipping profile update: previous update still in progress")
				apc.updateMutex.Unlock()
				continue
			}

			// Set the flag and release the lock before the potentially long-running call
			apc.updateInProgress = true
			apc.updateMutex.Unlock()

			// Run the update directly
			apc.updateAllProfiles(ctx)

			// Mark the update as complete
			apc.updateMutex.Lock()
			apc.updateInProgress = false
			apc.updateMutex.Unlock()

		case <-ctx.Done():
			logger.L().Info("ApplicationProfileCache periodic update stopped")
			return
		}
	}
}

// updateAllProfiles fetches all application profiles from storage and updates the cache
func (apc *ApplicationProfileCacheImpl) updateAllProfiles(ctx context.Context) {
	// Get unique namespaces from container info
	namespaces := apc.getNamespaces()
	if len(namespaces) == 0 {
		logger.L().Debug("no namespaces found in cache, skipping profile update")
		return
	}

	// Iterate over each namespace
	for _, namespace := range namespaces {
		// Get container IDs for this namespace
		containerIDs := apc.getContainerIDsForNamespace(namespace)
		if len(containerIDs) == 0 {
			logger.L().Debug("no containers found for namespace, skipping",
				helpers.String("namespace", namespace))
			continue
		}

		// Get profiles list for this namespace
		profileList, err := apc.storageClient.ApplicationProfiles(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.L().Error("failed to list application profiles",
				helpers.String("namespace", namespace),
				helpers.Error(err))
			continue
		}

		// Process each profile
		for _, profile := range profileList.Items {
			// Handle user-managed profiles
			if isUserManagedProfile(&profile) {
				apc.handleUserManagedProfile(&profile)
				continue
			}

			// Get the workload ID from profile
			workloadID := apc.wlidKey(profile.Annotations[helpersv1.WlidMetadataKey], profile.Labels[helpersv1.TemplateHashKey])
			if workloadID == "" {
				continue // this is the case for user-defined profiles
			}

			// Update profile state regardless of whether we'll update the full profile
			profileState := &objectcache.ProfileState{
				Completion: profile.Annotations[helpersv1.CompletionMetadataKey],
				Status:     profile.Annotations[helpersv1.StatusMetadataKey],
				Name:       profile.Name,
				Error:      nil,
			}
			apc.workloadIDToProfileState.Set(workloadID, profileState)

			// Only consider completed profiles
			if profile.Annotations[helpersv1.StatusMetadataKey] != helpersv1.Completed {
				continue
			}

			// Check if this workload ID is used by any container in this namespace
			workloadIDInUse := false
			hasNewContainer := false // Track if any container using this workload was seen from start
			for _, containerID := range containerIDs {
				if containerInfo, exists := apc.containerIDToInfo.Load(containerID); exists &&
					containerInfo.WorkloadID == workloadID &&
					containerInfo.InstanceTemplateHash == profile.Labels[helpersv1.TemplateHashKey] {
					workloadIDInUse = true
					// If any container was seen from start, mark it
					if containerInfo.SeenContainerFromTheStart {
						hasNewContainer = true
					}
				}
			}

			if !workloadIDInUse {
				continue
			}

			// If we have a "new" container (seen from start) and the profile is partial,
			// skip it - we don't want to use partial profiles for containers we're tracking from the start
			if hasNewContainer && profile.Annotations[helpersv1.CompletionMetadataKey] == helpersv1.Partial {
				logger.L().Debug("skipping partial profile for container seen from start",
					helpers.String("workloadID", workloadID),
					helpers.String("namespace", namespace))
				continue
			}

			// Update the profile in the cache
			if existingProfile, exists := apc.workloadIDToProfile.Load(workloadID); exists {
				// If the profile already exists and it's complete/completed, continue to the next one
				if existingProfile.Annotations[helpersv1.CompletionMetadataKey] == helpersv1.Full {
					continue
				}

				// If the new profile is not complete and we already have a completed/partial one, skip it
				if profile.Annotations[helpersv1.CompletionMetadataKey] != helpersv1.Full {
					continue
				}
			}

			// Fetch the profile from storage
			fullProfile, err := apc.storageClient.ApplicationProfiles(namespace).Get(ctx, profile.Name, metav1.GetOptions{})
			if err != nil {
				logger.L().Error("failed to get application profile",
					helpers.String("workloadID", workloadID),
					helpers.String("namespace", namespace),
					helpers.Error(err))
				// Update the profile state to indicate an error
				profileState.Error = err
				apc.workloadIDToProfileState.Set(workloadID, profileState)
				continue
			}

			apc.workloadIDToProfile.Set(workloadID, fullProfile)
			logger.L().Debug("updated profile in cache",
				helpers.String("workloadID", workloadID),
				helpers.String("namespace", namespace),
				helpers.String("status", profile.Annotations[helpersv1.StatusMetadataKey]),
				helpers.String("completion", profile.Annotations[helpersv1.CompletionMetadataKey]))

			// Update call stack search trees for containers using this workload ID
			for _, containerID := range containerIDs {
				if containerInfo, exists := apc.containerIDToInfo.Load(containerID); exists &&
					containerInfo.WorkloadID == workloadID &&
					containerInfo.InstanceTemplateHash == profile.Labels[helpersv1.TemplateHashKey] {
					// Create or update call stack search tree if not exists
					apc.indexContainerCallStacks(containerID, containerInfo.Name, fullProfile)
				}
			}
		}
		// Continue to next namespace
	}
}

// handleUserManagedProfile handles user-managed profiles
func (apc *ApplicationProfileCacheImpl) handleUserManagedProfile(profile *v1beta1.ApplicationProfile) {
	normalizedProfileName := strings.TrimPrefix(profile.Name, helpersv1.UserApplicationProfilePrefix)
	userManagedProfileUniqueIdentifier := profile.ResourceVersion + string(profile.UID)

	// Create a unique tracking key for this user profile
	profileKey := apc.profileKey(profile.Namespace, normalizedProfileName)

	// Check if we've already processed this exact version of the user-managed profile
	if storedIdentifier, exists := apc.profileToUserManagedIdentifier.Load(profileKey); exists &&
		storedIdentifier == userManagedProfileUniqueIdentifier {
		return
	}

	// Find and collect the profile to merge
	var toMerge struct {
		wlid    string
		profile *v1beta1.ApplicationProfile
	}

	apc.workloadIDToProfile.Range(func(wlid string, originalProfile *v1beta1.ApplicationProfile) bool {
		if originalProfile.Name == normalizedProfileName && originalProfile.Namespace == profile.Namespace {
			toMerge.wlid = wlid
			toMerge.profile = originalProfile
			logger.L().Debug("found matching profile for user-managed profile",
				helpers.String("workloadID", wlid),
				helpers.String("namespace", originalProfile.Namespace),
				helpers.String("profileName", originalProfile.Name))
			// Stop iteration
			return false
		}
		return true
	})

	// If we didn't find a matching profile, skip merging
	if toMerge.profile == nil {
		return
	}

	// Fetch the full user profile
	fullUserProfile, err := apc.storageClient.ApplicationProfiles(profile.Namespace).Get(
		context.Background(), profile.Name, metav1.GetOptions{})
	if err != nil {
		logger.L().Error("failed to get user-managed profile",
			helpers.String("namespace", profile.Namespace),
			helpers.String("profileName", profile.Name),
			helpers.Error(err))
		return
	}

	// Merge the user-managed profile with the normal profile

	// First, pull the original profile from the storage
	originalProfile, err := apc.storageClient.ApplicationProfiles(toMerge.profile.Namespace).Get(
		context.Background(), toMerge.profile.Name, metav1.GetOptions{})
	if err != nil {
		logger.L().Error("failed to get original profile",
			helpers.String("namespace", toMerge.profile.Namespace),
			helpers.String("profileName", toMerge.profile.Name),
			helpers.Error(err))
		return
	}
	// Merge the profiles
	mergedProfile := apc.performMerge(originalProfile, fullUserProfile)
	// Update the cache with the merged profile
	apc.workloadIDToProfile.Set(toMerge.wlid, mergedProfile)
	// Update profile state for the merged profile
	profileState := &objectcache.ProfileState{
		Completion: mergedProfile.Annotations[helpersv1.CompletionMetadataKey],
		Status:     mergedProfile.Annotations[helpersv1.StatusMetadataKey],
		Name:       mergedProfile.Name,
		Error:      nil,
	}
	apc.workloadIDToProfileState.Set(toMerge.wlid, profileState)

	logger.L().Debug("merged user-managed profile with normal profile",
		helpers.String("workloadID", toMerge.wlid),
		helpers.String("namespace", profile.Namespace),
		helpers.String("profileName", profile.Name))

	// We need to index the call stacks for the merged profile here, but currently we don't support that.

	// Record that we've processed this version of the profile
	apc.profileToUserManagedIdentifier.Set(profileKey, userManagedProfileUniqueIdentifier)
}

// indexContainerCallStacks builds the search index for a container's call stacks and removes them from the profile
func (apc *ApplicationProfileCacheImpl) indexContainerCallStacks(containerID, containerName string, appProfile *v1beta1.ApplicationProfile) {
	if appProfile == nil {
		logger.L().Warning("ApplicationProfileCacheImpl - application profile is nil",
			helpers.String("containerID", containerID),
			helpers.String("containerName", containerName))
		return
	}

	// Create a new call stack search tree
	callStackSearchTree := callstackcache.NewCallStackSearchTree()
	apc.containerToCallStackIndex.Set(containerID, &ContainerCallStackIndex{
		searchTree: callStackSearchTree,
	})

	// Iterate over the containers in the application profile
	// Find the container in the profile and index its call stacks
	for _, c := range appProfile.Spec.Containers {
		if c.Name == containerName {
			// Index all call stacks
			for _, stack := range c.IdentifiedCallStacks {
				callStackSearchTree.AddCallStack(stack)
			}

			// Clear the call stacks to free memory
			c.IdentifiedCallStacks = nil
			break
		}
	}

	// Also check init containers
	for _, c := range appProfile.Spec.InitContainers {
		if c.Name == containerName {
			for _, stack := range c.IdentifiedCallStacks {
				callStackSearchTree.AddCallStack(stack)
			}

			// Clear the call stacks to free memory
			c.IdentifiedCallStacks = nil
			break
		}
	}

	// And ephemeral containers
	for _, c := range appProfile.Spec.EphemeralContainers {
		if c.Name == containerName {
			for _, stack := range c.IdentifiedCallStacks {
				callStackSearchTree.AddCallStack(stack)
			}

			// Clear the call stacks to free memory
			c.IdentifiedCallStacks = nil
			break
		}
	}
}

// ContainerCallback handles container lifecycle events
func (apc *ApplicationProfileCacheImpl) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		if apc.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
			return
		}
		go apc.addContainerWithTimeout(notif.Container)
	case containercollection.EventTypeRemoveContainer:
		if apc.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
			return
		}
		go apc.deleteContainer(notif.Container.Runtime.ContainerID)
	}
}

// addContainerWithTimeout handles adding a container with a timeout to prevent hanging
func (apc *ApplicationProfileCacheImpl) addContainerWithTimeout(container *containercollection.Container) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- apc.addContainer(container, ctx)
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
func (apc *ApplicationProfileCacheImpl) addContainer(container *containercollection.Container, ctx context.Context) error {
	containerID := container.Runtime.ContainerID

	return apc.containerLocks.WithLockAndError(containerID, func() error {
		// Get workload ID from shared data
		sharedData, err := apc.waitForSharedContainerData(containerID, ctx)
		if err != nil {
			logger.L().Error("failed to get shared data for container",
				helpers.String("containerID", containerID),
				helpers.Error(err))
			return err
		}

		workloadID := apc.wlidKey(sharedData.Wlid, sharedData.InstanceID.GetTemplateHash())
		if workloadID == "" {
			logger.L().Debug("empty workloadID for container", helpers.String("containerID", containerID))
			return nil
		}

		// If container restarts and profile is partial, delete it from cache
		// This ensures we don't alert on activity we didn't see after restart
		if existingProfile, exists := apc.workloadIDToProfile.Load(workloadID); exists && !sharedData.PreRunningContainer {
			if existingProfile != nil && existingProfile.Annotations != nil {
				completion := existingProfile.Annotations[helpersv1.CompletionMetadataKey]
				if completion == helpersv1.Partial {
					logger.L().Debug("deleting partial profile on container restart",
						helpers.String("containerID", containerID),
						helpers.String("workloadID", workloadID),
						helpers.String("namespace", container.K8s.Namespace))

					// Delete the profile from cache
					profileKey := apc.profileKey(existingProfile.Namespace, existingProfile.Name)
					apc.profileToUserManagedIdentifier.Delete(profileKey)
					apc.workloadIDToProfile.Delete(workloadID)

					// Also delete call stack indices for all containers using this workload ID
					// (including the current container if it exists from a previous run)
					apc.containerToCallStackIndex.Delete(containerID)
					apc.containerIDToInfo.Range(func(cID string, info *ContainerInfo) bool {
						if info.WorkloadID == workloadID {
							apc.containerToCallStackIndex.Delete(cID)
						}
						return true
					})
				}
			}
		} else {
			apc.workloadIDToProfileState.Set(workloadID, nil)
		}

		// Create container info
		// Mark container as "seen from start" if it is not pre-running
		containerInfo := &ContainerInfo{
			ContainerID:               containerID,
			WorkloadID:                workloadID,
			InstanceTemplateHash:      sharedData.InstanceID.GetTemplateHash(),
			Namespace:                 container.K8s.Namespace,
			Name:                      container.Runtime.ContainerName,
			SeenContainerFromTheStart: !sharedData.PreRunningContainer,
		}

		// Check for user-defined profile
		if userDefinedProfile, ok := container.K8s.PodLabels[helpersv1.UserDefinedProfileMetadataKey]; ok {
			if userDefinedProfile != "" {
				// Set the user-defined profile in container info
				containerInfo.UserDefinedProfile = userDefinedProfile
				// Fetch the profile from storage
				// TODO should we cache user-defined profiles separately? - it could allow deduplication
				fullProfile, err := apc.storageClient.ApplicationProfiles(container.K8s.Namespace).Get(ctx, userDefinedProfile, metav1.GetOptions{})
				if err != nil {
					logger.L().Error("failed to get user-defined profile",
						helpers.String("containerID", containerID),
						helpers.String("workloadID", workloadID),
						helpers.String("namespace", container.K8s.Namespace),
						helpers.String("profileName", userDefinedProfile),
						helpers.Error(err))
					// Update the profile state to indicate an error
					profileState := &objectcache.ProfileState{
						Error: err,
					}
					apc.workloadIDToProfileState.Set(workloadID, profileState)
					return nil
				}
				// Update the profile in the cache
				apc.workloadIDToProfile.Set(workloadID, fullProfile)
				logger.L().Debug("added user-defined profile to cache",
					helpers.String("containerID", containerID),
					helpers.String("workloadID", workloadID),
					helpers.String("namespace", container.K8s.Namespace),
					helpers.String("profileName", userDefinedProfile))
			}
		}

		// Add to container info map
		apc.containerIDToInfo.Set(containerID, containerInfo)

		logger.L().Debug("container added to cache",
			helpers.String("containerID", containerID),
			helpers.String("workloadID", workloadID),
			helpers.String("namespace", container.K8s.Namespace))

		return nil
	})
}

// deleteContainer deletes a container from the cache
func (apc *ApplicationProfileCacheImpl) deleteContainer(containerID string) {
	apc.containerLocks.WithLock(containerID, func() {
		// Get container info
		containerInfo, exists := apc.containerIDToInfo.Load(containerID)
		if !exists {
			logger.L().Debug("containerID not found in cache", helpers.String("containerID", containerID))
			return
		}

		// Clean up container info and call stack index
		apc.containerIDToInfo.Delete(containerID)
		apc.containerToCallStackIndex.Delete(containerID)

		// Check if any other container is using the same workload ID
		workloadStillInUse := false
		apc.containerIDToInfo.Range(func(_ string, info *ContainerInfo) bool {
			if info.WorkloadID == containerInfo.WorkloadID {
				workloadStillInUse = true
				return false // Stop iteration
			}
			return true // Continue iteration
		})

		// If no other container is using the same workload ID, delete it from the cache
		if !workloadStillInUse {
			if profile, exists := apc.workloadIDToProfile.Load(containerInfo.WorkloadID); exists {
				// Remove the profile from the cache
				profileKey := apc.profileKey(profile.Namespace, profile.Name)
				apc.profileToUserManagedIdentifier.Delete(profileKey)
			}
			apc.workloadIDToProfileState.Delete(containerInfo.WorkloadID)
			apc.workloadIDToProfile.Delete(containerInfo.WorkloadID)
			logger.L().Debug("deleted workloadID from cache", helpers.String("workloadID", containerInfo.WorkloadID))
		}
	})

	// Clean up the lock when done - call this outside the WithLock closure
	apc.containerLocks.ReleaseLock(containerID)
}

// waitForSharedContainerData waits for shared container data to be available
func (apc *ApplicationProfileCacheImpl) waitForSharedContainerData(containerID string, ctx context.Context) (*objectcache.WatchedContainerData, error) {
	return backoff.Retry(ctx, func() (*objectcache.WatchedContainerData, error) {
		if sharedData := apc.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

func (apc *ApplicationProfileCacheImpl) profileKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func (apc *ApplicationProfileCacheImpl) wlidKey(wlid, templateHash string) string {
	return fmt.Sprintf("%s/%s", wlid, templateHash)
}

func (apc *ApplicationProfileCacheImpl) performMerge(normalProfile, userManagedProfile *v1beta1.ApplicationProfile) *v1beta1.ApplicationProfile {
	mergedProfile := normalProfile.DeepCopy()

	// Merge spec
	mergedProfile.Spec.Containers = apc.mergeContainers(mergedProfile.Spec.Containers, userManagedProfile.Spec.Containers)
	mergedProfile.Spec.InitContainers = apc.mergeContainers(mergedProfile.Spec.InitContainers, userManagedProfile.Spec.InitContainers)
	mergedProfile.Spec.EphemeralContainers = apc.mergeContainers(mergedProfile.Spec.EphemeralContainers, userManagedProfile.Spec.EphemeralContainers)

	return mergedProfile
}

func (apc *ApplicationProfileCacheImpl) mergeContainers(normalContainers, userManagedContainers []v1beta1.ApplicationProfileContainer) []v1beta1.ApplicationProfileContainer {
	if len(userManagedContainers) != len(normalContainers) {
		// If the number of containers don't match, we can't merge
		logger.L().Warning("ApplicationProfileCacheImpl - failed to merge user-managed profile with base profile",
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
				apc.mergeContainer(&normalContainers[i], &userContainer)
				break
			}
		}
	}
	return normalContainers
}

func (apc *ApplicationProfileCacheImpl) mergeContainer(normalContainer, userContainer *v1beta1.ApplicationProfileContainer) {
	normalContainer.Capabilities = append(normalContainer.Capabilities, userContainer.Capabilities...)
	normalContainer.Execs = append(normalContainer.Execs, userContainer.Execs...)
	normalContainer.Opens = append(normalContainer.Opens, userContainer.Opens...)
	normalContainer.Syscalls = append(normalContainer.Syscalls, userContainer.Syscalls...)
	normalContainer.Endpoints = append(normalContainer.Endpoints, userContainer.Endpoints...)
	for k, v := range userContainer.PolicyByRuleId {
		if existingPolicy, exists := normalContainer.PolicyByRuleId[k]; exists {
			normalContainer.PolicyByRuleId[k] = utils.MergePolicies(existingPolicy, v)
		} else {
			normalContainer.PolicyByRuleId[k] = v
		}
	}
}

func isUserManagedProfile(appProfile *v1beta1.ApplicationProfile) bool {
	return appProfile.Annotations != nil &&
		appProfile.Annotations[helpersv1.ManagedByMetadataKey] == helpersv1.ManagedByUserValue &&
		strings.HasPrefix(appProfile.GetName(), helpersv1.UserApplicationProfilePrefix)
}

// GetApplicationProfile gets the application profile for a container
func (apc *ApplicationProfileCacheImpl) GetApplicationProfile(containerID string) *v1beta1.ApplicationProfile {
	// Get container info
	if containerInfo, exists := apc.containerIDToInfo.Load(containerID); exists {
		workloadID := containerInfo.WorkloadID
		if workloadID == "" {
			return nil
		}

		// Try to get profile from cache
		if profile, exists := apc.workloadIDToProfile.Load(workloadID); exists {
			if profile != nil {
				return profile
			}
		}
	}

	return nil
}

// GetApplicationProfileState gets the profile state for a container
func (apc *ApplicationProfileCacheImpl) GetApplicationProfileState(containerID string) *objectcache.ProfileState {
	// Get container info
	containerInfo, exists := apc.containerIDToInfo.Load(containerID)
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
	if profileState, exists := apc.workloadIDToProfileState.Load(workloadID); exists {
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

// GetCallStackSearchTree gets the call stack index for a container
func (apc *ApplicationProfileCacheImpl) GetCallStackSearchTree(containerID string) *callstackcache.CallStackSearchTree {
	if index, exist := apc.containerToCallStackIndex.Load(containerID); exist {
		return index.searchTree
	}

	return nil
}

// getNamespaces retrieves all unique namespaces from the container info cache
func (apc *ApplicationProfileCacheImpl) getNamespaces() []string {
	namespaceSet := mapset.NewSet[string]()
	apc.containerIDToInfo.Range(func(_ string, info *ContainerInfo) bool {
		namespaceSet.Add(info.Namespace)
		return true
	})
	return namespaceSet.ToSlice()
}

// getContainerIDsForNamespace retrieves all container IDs for a given namespace
func (apc *ApplicationProfileCacheImpl) getContainerIDsForNamespace(namespace string) []string {
	containerIDs := []string{}
	apc.containerIDToInfo.Range(func(containerID string, info *ContainerInfo) bool {
		if info.Namespace == namespace {
			containerIDs = append(containerIDs, containerID)
		}
		return true
	})
	return containerIDs
}

// Ensure ApplicationProfileCacheImpl implements the ApplicationProfileCache interface
var _ objectcache.ApplicationProfileCache = (*ApplicationProfileCacheImpl)(nil)
