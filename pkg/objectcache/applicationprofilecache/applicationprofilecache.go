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
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	versioned "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContainerInfo holds container metadata we need for application profile mapping
type ContainerInfo struct {
	ContainerID string
	WorkloadID  string
	Namespace   string
}

// ContainerCallStackIndex maintains call stack search trees for a container
type ContainerCallStackIndex struct {
	searchTree *callstackcache.CallStackSearchTree
}

type ApplicationProfileCacheImpl struct {
	cfg                            config.Config
	workloadIDToProfile            maps.SafeMap[string, *v1beta1.ApplicationProfile]
	containerIDToInfo              maps.SafeMap[string, *ContainerInfo]
	namespaceToContainers          maps.SafeMap[string, mapset.Set[string]] // namespace -> set of containerIDs
	profileToUserManagedIdentifier maps.SafeMap[string, string]             // profileName -> user-managed profile unique identifier (This is used to prevent merging the same user-managed profile multiple times)
	containerToCallStackIndex      maps.SafeMap[string, *ContainerCallStackIndex]
	storageClient                  versioned.SpdxV1beta1Interface
	k8sObjectCache                 objectcache.K8sObjectCache
	updateInterval                 time.Duration
	mutex                          sync.Mutex // For operations that need additional synchronization
}

// NewApplicationProfileCache creates a new application profile cache with periodic updates
func NewApplicationProfileCache(cfg config.Config, storageClient versioned.SpdxV1beta1Interface, k8sObjectCache objectcache.K8sObjectCache) *ApplicationProfileCacheImpl {
	updateInterval := utils.AddJitter(cfg.ProfilesCacheRefreshRate, 10) // Add 10% jitter to avoid high load on the storage

	apc := &ApplicationProfileCacheImpl{
		cfg:                       cfg,
		workloadIDToProfile:       maps.SafeMap[string, *v1beta1.ApplicationProfile]{},
		containerIDToInfo:         maps.SafeMap[string, *ContainerInfo]{},
		namespaceToContainers:     maps.SafeMap[string, mapset.Set[string]]{},
		containerToCallStackIndex: maps.SafeMap[string, *ContainerCallStackIndex]{},
		storageClient:             storageClient,
		k8sObjectCache:            k8sObjectCache,
		updateInterval:            updateInterval,
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
			apc.updateAllProfiles(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// updateAllProfiles fetches all application profiles from storage and updates the cache
func (apc *ApplicationProfileCacheImpl) updateAllProfiles(ctx context.Context) {
	// Process namespace by namespace to optimize LIST operations
	apc.namespaceToContainers.Range(func(namespace string, containerSet mapset.Set[string]) bool {
		// Skip empty namespaces
		if containerSet.Cardinality() == 0 {
			return true
		}

		logger.L().Debug("updating profiles for namespace", helpers.String("namespace", namespace))

		// Get profiles list for this namespace
		profileList, err := apc.storageClient.ApplicationProfiles(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.L().Error("failed to list application profiles",
				helpers.String("namespace", namespace),
				helpers.Error(err))
			return true // Continue to next namespace
		}

		// Process each profile
		for _, profile := range profileList.Items {
			// Handle user-managed profiles
			if isUserManagedProfile(&profile) {
				apc.handleUserManagedProfile(&profile)
				continue
			}

			// Only consider completed profiles
			if profile.Annotations[helpersv1.StatusMetadataKey] != helpersv1.Completed {
				continue
			}

			// Get the workload ID from profile
			workloadID := profile.Annotations[helpersv1.WlidMetadataKey]
			if workloadID == "" {
				continue
			}

			// Check if this workload ID is used by any container in this namespace
			workloadIDInUse := false
			for containerID := range containerSet.Iter() {
				if containerInfo, exists := apc.containerIDToInfo.Load(containerID); exists &&
					containerInfo.WorkloadID == workloadID {
					workloadIDInUse = true
					break
				}
			}

			if !workloadIDInUse {
				continue
			}

			// Update the profile in the cache
			if existingProfile, exists := apc.workloadIDToProfile.Load(workloadID); exists {
				// If the profile already exists and it's complete/completed, continue to the next one
				if existingProfile.Annotations[helpersv1.CompletionMetadataKey] == helpersv1.Complete {
					continue
				}

				// If the new profile is not complete and we already have a completed/partial one, skip it
				if profile.Annotations[helpersv1.CompletionMetadataKey] != helpersv1.Complete {
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
				continue
			}

			apc.workloadIDToProfile.Set(workloadID, fullProfile)
			logger.L().Debug("updated profile in cache",
				helpers.String("workloadID", workloadID),
				helpers.String("namespace", namespace))

			// Update call stack search trees for containers using this workload ID
			for containerID := range containerSet.Iter() {
				if containerInfo, exists := apc.containerIDToInfo.Load(containerID); exists &&
					containerInfo.WorkloadID == workloadID {
					// Create or update call stack search tree if not exists
					if _, exists := apc.containerToCallStackIndex.Load(containerID); !exists {
						// Index the call stacks for this container
						apc.indexContainerCallStacks(containerID, containerInfo.ContainerID, fullProfile)
						logger.L().Debug("created call stack search tree for container",
							helpers.String("containerID", containerID))
					}
				}
			}
		}
		return true // Continue to next namespace
	})
}

// handleUserManagedProfile handles user-managed profiles
func (apc *ApplicationProfileCacheImpl) handleUserManagedProfile(profile *v1beta1.ApplicationProfile) {
	normalizedProfileName := strings.TrimPrefix(profile.Name, "ug-")
	userManagedProfileUniqueIdentifier := profile.ResourceVersion + string(profile.UID)

	apc.workloadIDToProfile.Range(func(wlid string, originalProfile *v1beta1.ApplicationProfile) bool {
		if originalProfile.Name == normalizedProfileName && originalProfile.Namespace == profile.Namespace {
			// Check if we already merged this user-managed profile
			if userManagedProfileUniqueId, exists := apc.profileToUserManagedIdentifier.Load(originalProfile.Name); exists {
				if userManagedProfileUniqueId == userManagedProfileUniqueIdentifier {
					logger.L().Debug("user-managed profile already merged, skipping",
						helpers.String("workloadID", wlid),
						helpers.String("namespace", profile.Namespace),
						helpers.String("profileName", profile.Name))
					return false // Stop iteration
				}
			}
			// Store the user-managed profile unique identifier to prevent merging it again
			apc.profileToUserManagedIdentifier.Set(originalProfile.Name, userManagedProfileUniqueIdentifier)
			// Fetch the full profile from storage
			fullProfile, err := apc.storageClient.ApplicationProfiles(profile.Namespace).Get(context.Background(), profile.Name, metav1.GetOptions{})
			if err != nil {
				logger.L().Error("failed to get user-managed profile",
					helpers.String("workloadID", wlid),
					helpers.String("namespace", profile.Namespace),
					helpers.String("profileName", profile.Name),
					helpers.Error(err))
				return false // Stop iteration
			}
			profile = fullProfile
			// Merge the user-managed profile with the normal profile
			mergedProfile := apc.performMerge(originalProfile, profile)
			apc.workloadIDToProfile.Set(wlid, mergedProfile)
			logger.L().Debug("merged user-managed profile with normal profile",
				helpers.String("workloadID", wlid),
				helpers.String("namespace", profile.Namespace),
				helpers.String("profileName", profile.Name))
			return false // Stop iteration
		}
		return true // Continue iteration
	},
	)
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
		go func() {
			if err := apc.addContainer(notif.Container); err != nil {
				logger.L().Error("failed to add container to the cache", helpers.Error(err))
			}
		}()
	case containercollection.EventTypeRemoveContainer:
		apc.deleteContainer(notif.Container.Runtime.ContainerID)
	}
}

// addContainer adds a container to the cache
func (apc *ApplicationProfileCacheImpl) addContainer(container *containercollection.Container) error {
	// Get container ID and namespace directly from container
	containerID := container.Runtime.ContainerID
	namespace := container.K8s.Namespace

	// Get workload ID from shared data
	sharedData, err := apc.waitForSharedContainerData(containerID)
	if err != nil {
		logger.L().Error("failed to get shared data for container",
			helpers.String("containerID", containerID),
			helpers.Error(err))
		return err
	}

	workloadID := sharedData.Wlid
	if workloadID == "" {
		logger.L().Debug("empty workloadID for container", helpers.String("containerID", containerID))
		return nil
	}

	// Create container info
	containerInfo := &ContainerInfo{
		ContainerID: containerID,
		WorkloadID:  workloadID,
		Namespace:   namespace,
	}

	// Add to container info map
	apc.containerIDToInfo.Set(containerID, containerInfo)

	// Add to namespace -> containers mapping
	apc.mutex.Lock()
	containerSet, exists := apc.namespaceToContainers.Load(namespace)
	if !exists || containerSet == nil {
		containerSet = mapset.NewSet[string]()
		apc.namespaceToContainers.Set(namespace, containerSet)
	}
	containerSet.Add(containerID)
	apc.mutex.Unlock()

	logger.L().Debug("container added to cache",
		helpers.String("containerID", containerID),
		helpers.String("workloadID", workloadID),
		helpers.String("namespace", namespace))

	return nil
}

// deleteContainer deletes a container from the cache
func (apc *ApplicationProfileCacheImpl) deleteContainer(containerID string) {
	// Get container info
	containerInfo, exists := apc.containerIDToInfo.Load(containerID)
	if !exists {
		logger.L().Debug("containerID not found in cache", helpers.String("containerID", containerID))
		return
	}

	// Clean up namespace -> containers mapping
	apc.mutex.Lock()
	if containerSet, exists := apc.namespaceToContainers.Load(containerInfo.Namespace); exists {
		containerSet.Remove(containerID)
	}
	apc.mutex.Unlock()

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
		apc.workloadIDToProfile.Delete(containerInfo.WorkloadID)
		logger.L().Debug("deleted workloadID from cache", helpers.String("workloadID", containerInfo.WorkloadID))
	}
}

// waitForSharedContainerData waits for shared container data to be available
func (apc *ApplicationProfileCacheImpl) waitForSharedContainerData(containerID string) (*utils.WatchedContainerData, error) {
	return backoff.Retry(context.Background(), func() (*utils.WatchedContainerData, error) {
		if sharedData := apc.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
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
		appProfile.Annotations["kubescape.io/managed-by"] == "User" &&
		strings.HasPrefix(appProfile.GetName(), "ug-")
}

// GetApplicationProfile gets the application profile for a container
func (apc *ApplicationProfileCacheImpl) GetApplicationProfile(containerID string) *v1beta1.ApplicationProfile {
	// Get container info
	containerInfo, exists := apc.containerIDToInfo.Load(containerID)
	if !exists {
		return nil
	}

	workloadID := containerInfo.WorkloadID
	if workloadID == "" {
		return nil
	}

	// Try to get profile from cache
	profile, exists := apc.workloadIDToProfile.Load(workloadID)
	if exists && profile != nil {
		return profile
	}

	return nil
}

// GetCallStackSearchTree gets the call stack index for a container
func (apc *ApplicationProfileCacheImpl) GetCallStackSearchTree(containerID string) *callstackcache.CallStackSearchTree {
	if index, exist := apc.containerToCallStackIndex.Load(containerID); exist {
		return index.searchTree
	}

	return nil
}

// Ensure ApplicationProfileCacheImpl implements the ApplicationProfileCache interface
var _ objectcache.ApplicationProfileCache = (*ApplicationProfileCacheImpl)(nil)
