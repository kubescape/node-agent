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

// ContainerInfo holds essential container metadata for profile mapping
type ContainerInfo struct {
	ContainerID          string
	WorkloadID           string
	InstanceTemplateHash string
	Namespace            string
	Name                 string
}

// ContainerCallStackIndex maintains optimized call stack search trees
type ContainerCallStackIndex struct {
	searchTree *callstackcache.CallStackSearchTree
}

// ProfileKey represents a unique profile identifier
type ProfileKey string

func (pk ProfileKey) String() string {
	return string(pk)
}

// ApplicationProfileCache implements efficient application profile caching with periodic updates
type ApplicationProfileCache struct {
	// Configuration
	cfg            config.Config
	storageClient  versioned.SpdxV1beta1Interface
	k8sObjectCache objectcache.K8sObjectCache
	updateInterval time.Duration

	// Core mappings
	workloadProfiles    maps.SafeMap[string, *v1beta1.ApplicationProfile]
	workloadStates      maps.SafeMap[string, *objectcache.ProfileState]
	containerInfo       maps.SafeMap[string, *ContainerInfo]
	namespaceContainers maps.SafeMap[string, mapset.Set[string]]
	callStackIndices    maps.SafeMap[string, *ContainerCallStackIndex]

	// User-managed profile tracking
	userProfileIdentifiers maps.SafeMap[ProfileKey, string]

	// Synchronization
	mu               sync.RWMutex
	updateInProgress bool
	updateMu         sync.Mutex
}

// NewApplicationProfileCache creates a new cache instance with jittered update intervals
func NewApplicationProfileCache(
	cfg config.Config,
	storageClient versioned.SpdxV1beta1Interface,
	k8sObjectCache objectcache.K8sObjectCache,
) *ApplicationProfileCache {
	return &ApplicationProfileCache{
		cfg:                    cfg,
		storageClient:          storageClient,
		k8sObjectCache:         k8sObjectCache,
		updateInterval:         utils.AddJitter(cfg.ProfilesCacheRefreshRate, 10),
		workloadProfiles:       maps.SafeMap[string, *v1beta1.ApplicationProfile]{},
		workloadStates:         maps.SafeMap[string, *objectcache.ProfileState]{},
		containerInfo:          maps.SafeMap[string, *ContainerInfo]{},
		namespaceContainers:    maps.SafeMap[string, mapset.Set[string]]{},
		callStackIndices:       maps.SafeMap[string, *ContainerCallStackIndex]{},
		userProfileIdentifiers: maps.SafeMap[ProfileKey, string]{},
	}
}

// Start initiates the periodic profile update process
func (apc *ApplicationProfileCache) Start(ctx context.Context) {
	go apc.runPeriodicUpdates(ctx)
}

// runPeriodicUpdates manages the periodic profile refresh cycle
func (apc *ApplicationProfileCache) runPeriodicUpdates(ctx context.Context) {
	ticker := time.NewTicker(apc.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if apc.shouldSkipUpdate() {
				logger.L().Debug("skipping profile update: previous update still in progress")
				continue
			}

			apc.setUpdateInProgress(true)
			apc.refreshAllProfiles(ctx)
			apc.setUpdateInProgress(false)

		case <-ctx.Done():
			logger.L().Info("ApplicationProfileCache periodic update stopped")
			return
		}
	}
}

// shouldSkipUpdate checks if an update is already in progress
func (apc *ApplicationProfileCache) shouldSkipUpdate() bool {
	apc.updateMu.Lock()
	defer apc.updateMu.Unlock()
	return apc.updateInProgress
}

// setUpdateInProgress safely sets the update progress flag
func (apc *ApplicationProfileCache) setUpdateInProgress(inProgress bool) {
	apc.updateMu.Lock()
	defer apc.updateMu.Unlock()
	apc.updateInProgress = inProgress
}

// refreshAllProfiles fetches and updates all application profiles from storage
func (apc *ApplicationProfileCache) refreshAllProfiles(ctx context.Context) {
	namespaces := apc.getActiveNamespaces()

	for namespace, containerSet := range namespaces {
		if containerSet.Cardinality() == 0 {
			continue
		}
		apc.refreshNamespaceProfiles(ctx, namespace, containerSet)
	}
}

// getActiveNamespaces returns a snapshot of namespace to container mappings
func (apc *ApplicationProfileCache) getActiveNamespaces() map[string]mapset.Set[string] {
	apc.mu.RLock()
	defer apc.mu.RUnlock()

	namespaces := make(map[string]mapset.Set[string])
	apc.namespaceContainers.Range(func(namespace string, containerSet mapset.Set[string]) bool {
		namespaces[namespace] = containerSet
		return true
	})
	return namespaces
}

// refreshNamespaceProfiles updates profiles for a specific namespace
func (apc *ApplicationProfileCache) refreshNamespaceProfiles(ctx context.Context, namespace string, containerSet mapset.Set[string]) {
	profileList, err := apc.storageClient.ApplicationProfiles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.L().Error("failed to list application profiles",
			helpers.String("namespace", namespace),
			helpers.Error(err))
		return
	}

	for _, profile := range profileList.Items {
		if apc.isUserManagedProfile(&profile) {
			apc.handleUserManagedProfile(&profile)
		} else {
			apc.handleStandardProfile(ctx, &profile, containerSet)
		}
	}
}

// handleStandardProfile processes regular (non-user-managed) profiles
func (apc *ApplicationProfileCache) handleStandardProfile(ctx context.Context, profile *v1beta1.ApplicationProfile, containerSet mapset.Set[string]) {
	workloadID := profile.Annotations[helpersv1.WlidMetadataKey]
	if workloadID == "" {
		return
	}

	// Always update profile state
	profileState := &objectcache.ProfileState{
		Completion: profile.Annotations[helpersv1.CompletionMetadataKey],
		Status:     profile.Annotations[helpersv1.StatusMetadataKey],
		Name:       profile.Name,
		Error:      nil,
	}
	apc.workloadStates.Set(workloadID, profileState)

	// Only process completed profiles
	if profile.Annotations[helpersv1.StatusMetadataKey] != helpersv1.Completed {
		return
	}

	if !apc.isWorkloadInUse(workloadID, profile.Labels[helpersv1.TemplateHashKey], containerSet) {
		return
	}

	if apc.shouldSkipProfileUpdate(workloadID, profile) {
		return
	}

	fullProfile, err := apc.fetchFullProfile(ctx, profile)
	if err != nil {
		profileState.Error = err
		apc.workloadStates.Set(workloadID, profileState)
		return
	}

	apc.updateProfileAndIndices(workloadID, fullProfile, containerSet)
}

// isWorkloadInUse checks if a workload ID is currently used by any container
func (apc *ApplicationProfileCache) isWorkloadInUse(workloadID, templateHash string, containerSet mapset.Set[string]) bool {
	for containerID := range containerSet.Iter() {
		apc.mu.RLock()
		containerInfo, exists := apc.containerInfo.Load(containerID)
		apc.mu.RUnlock()

		if exists && containerInfo.WorkloadID == workloadID && containerInfo.InstanceTemplateHash == templateHash {
			return true
		}
	}
	return false
}

// shouldSkipProfileUpdate determines if a profile update should be skipped
func (apc *ApplicationProfileCache) shouldSkipProfileUpdate(workloadID string, newProfile *v1beta1.ApplicationProfile) bool {
	existingProfile, exists := apc.workloadProfiles.Load(workloadID)
	if !exists {
		return false
	}

	// Skip if existing profile is complete
	if existingProfile.Annotations[helpersv1.CompletionMetadataKey] == helpersv1.Complete {
		return true
	}

	// Skip if new profile is not complete and we have a partial one
	return newProfile.Annotations[helpersv1.CompletionMetadataKey] != helpersv1.Complete
}

// fetchFullProfile retrieves the complete profile from storage
func (apc *ApplicationProfileCache) fetchFullProfile(ctx context.Context, profile *v1beta1.ApplicationProfile) (*v1beta1.ApplicationProfile, error) {
	return apc.storageClient.ApplicationProfiles(profile.Namespace).Get(ctx, profile.Name, metav1.GetOptions{})
}

// updateProfileAndIndices updates the profile cache and call stack indices
func (apc *ApplicationProfileCache) updateProfileAndIndices(workloadID string, profile *v1beta1.ApplicationProfile, containerSet mapset.Set[string]) {
	apc.workloadProfiles.Set(workloadID, profile)

	logger.L().Debug("updated profile in cache",
		helpers.String("workloadID", workloadID),
		helpers.String("namespace", profile.Namespace),
		helpers.String("status", profile.Annotations[helpersv1.StatusMetadataKey]),
		helpers.String("completion", profile.Annotations[helpersv1.CompletionMetadataKey]))

	// Update call stack indices for matching containers
	templateHash := profile.Labels[helpersv1.TemplateHashKey]
	for containerID := range containerSet.Iter() {
		apc.mu.RLock()
		containerInfo, exists := apc.containerInfo.Load(containerID)
		apc.mu.RUnlock()

		if exists && containerInfo.WorkloadID == workloadID && containerInfo.InstanceTemplateHash == templateHash {
			apc.indexContainerCallStacks(containerID, containerInfo.Name, profile)
		}
	}
}

// handleUserManagedProfile processes user-managed profiles and merges them with base profiles
func (apc *ApplicationProfileCache) handleUserManagedProfile(profile *v1beta1.ApplicationProfile) {
	normalizedName := strings.TrimPrefix(profile.Name, helpersv1.UserApplicationProfilePrefix)
	uniqueIdentifier := profile.ResourceVersion + string(profile.UID)
	profileKey := apc.createProfileKey(profile.Namespace, normalizedName)

	// Skip if already processed this version
	if storedID, exists := apc.userProfileIdentifiers.Load(profileKey); exists && storedID == uniqueIdentifier {
		return
	}

	// Find matching base profile
	baseWorkloadID, baseProfile := apc.findMatchingBaseProfile(normalizedName, profile.Namespace)
	if baseProfile == nil {
		return
	}

	// Fetch and merge profiles
	fullUserProfile, err := apc.fetchFullProfile(context.Background(), profile)
	if err != nil {
		logger.L().Error("failed to get user-managed profile",
			helpers.String("namespace", profile.Namespace),
			helpers.String("profileName", profile.Name),
			helpers.Error(err))
		return
	}

	originalProfile, err := apc.fetchFullProfile(context.Background(), baseProfile)
	if err != nil {
		logger.L().Error("failed to get original profile",
			helpers.String("namespace", baseProfile.Namespace),
			helpers.String("profileName", baseProfile.Name),
			helpers.Error(err))
		return
	}

	mergedProfile := apc.mergeProfiles(originalProfile, fullUserProfile)
	apc.updateMergedProfile(baseWorkloadID, mergedProfile)
	apc.userProfileIdentifiers.Set(profileKey, uniqueIdentifier)
}

// findMatchingBaseProfile locates the base profile for user-managed profile merging
func (apc *ApplicationProfileCache) findMatchingBaseProfile(profileName, namespace string) (string, *v1beta1.ApplicationProfile) {
	var workloadID string
	var profile *v1beta1.ApplicationProfile

	apc.workloadProfiles.Range(func(wlid string, p *v1beta1.ApplicationProfile) bool {
		if p.Name == profileName && p.Namespace == namespace {
			workloadID = wlid
			profile = p
			return false // Stop iteration
		}
		return true
	})

	return workloadID, profile
}

// updateMergedProfile updates cache with merged profile and its state
func (apc *ApplicationProfileCache) updateMergedProfile(workloadID string, mergedProfile *v1beta1.ApplicationProfile) {
	apc.workloadProfiles.Set(workloadID, mergedProfile)

	profileState := &objectcache.ProfileState{
		Completion: mergedProfile.Annotations[helpersv1.CompletionMetadataKey],
		Status:     mergedProfile.Annotations[helpersv1.StatusMetadataKey],
		Name:       mergedProfile.Name,
		Error:      nil,
	}
	apc.workloadStates.Set(workloadID, profileState)

	logger.L().Debug("merged user-managed profile with base profile",
		helpers.String("workloadID", workloadID),
		helpers.String("namespace", mergedProfile.Namespace))
}

// indexContainerCallStacks builds search indices for container call stacks
func (apc *ApplicationProfileCache) indexContainerCallStacks(containerID, containerName string, appProfile *v1beta1.ApplicationProfile) {
	if appProfile == nil {
		logger.L().Warning("application profile is nil",
			helpers.String("containerID", containerID),
			helpers.String("containerName", containerName))
		return
	}

	searchTree := callstackcache.NewCallStackSearchTree()
	apc.callStackIndices.Set(containerID, &ContainerCallStackIndex{searchTree: searchTree})

	// Index call stacks from all container types
	apc.indexCallStacksFromContainers(searchTree, containerName, appProfile.Spec.Containers)
	apc.indexCallStacksFromContainers(searchTree, containerName, appProfile.Spec.InitContainers)
	apc.indexCallStacksFromContainers(searchTree, containerName, appProfile.Spec.EphemeralContainers)
}

// indexCallStacksFromContainers extracts and indexes call stacks from container specifications
func (apc *ApplicationProfileCache) indexCallStacksFromContainers(searchTree *callstackcache.CallStackSearchTree, containerName string, containers []v1beta1.ApplicationProfileContainer) {
	for i := range containers {
		if containers[i].Name == containerName {
			for _, stack := range containers[i].IdentifiedCallStacks {
				searchTree.AddCallStack(stack)
			}
			// Clear call stacks to free memory
			containers[i].IdentifiedCallStacks = nil
			break
		}
	}
}

// ContainerCallback handles container lifecycle events
func (apc *ApplicationProfileCache) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		go func() {
			if err := apc.addContainer(notif.Container); err != nil {
				logger.L().Error("failed to add container to cache", helpers.Error(err))
			}
		}()
	case containercollection.EventTypeRemoveContainer:
		go apc.removeContainer(notif.Container.Runtime.ContainerID)
	}
}

// addContainer registers a new container in the cache
func (apc *ApplicationProfileCache) addContainer(container *containercollection.Container) error {
	containerID := container.Runtime.ContainerID
	namespace := container.K8s.Namespace

	sharedData, err := apc.waitForSharedData(containerID)
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
		Name:                 container.Runtime.ContainerName,
	}

	apc.mu.Lock()
	defer apc.mu.Unlock()

	apc.containerInfo.Set(containerID, containerInfo)
	apc.addContainerToNamespace(namespace, containerID)
	apc.ensureWorkloadStateExists(workloadID)

	logger.L().Debug("container added to cache",
		helpers.String("containerID", containerID),
		helpers.String("workloadID", workloadID),
		helpers.String("namespace", namespace))

	return nil
}

// addContainerToNamespace adds a container to the namespace mapping
func (apc *ApplicationProfileCache) addContainerToNamespace(namespace, containerID string) {
	containerSet, exists := apc.namespaceContainers.Load(namespace)
	if !exists || containerSet == nil {
		containerSet = mapset.NewSet[string]()
		apc.namespaceContainers.Set(namespace, containerSet)
	}
	containerSet.Add(containerID)
}

// ensureWorkloadStateExists initializes workload state if it doesn't exist
func (apc *ApplicationProfileCache) ensureWorkloadStateExists(workloadID string) {
	if _, exists := apc.workloadStates.Load(workloadID); !exists {
		apc.workloadStates.Set(workloadID, nil)
	}
}

// removeContainer removes a container and cleans up associated resources
func (apc *ApplicationProfileCache) removeContainer(containerID string) {
	apc.mu.Lock()
	defer apc.mu.Unlock()

	containerInfo, exists := apc.containerInfo.Load(containerID)
	if !exists {
		logger.L().Debug("containerID not found in cache", helpers.String("containerID", containerID))
		return
	}

	apc.cleanupNamespaceMapping(containerInfo)
	apc.cleanupContainerResources(containerID)
	apc.cleanupUnusedWorkload(containerInfo.WorkloadID)
}

// cleanupNamespaceMapping removes container from namespace mapping
func (apc *ApplicationProfileCache) cleanupNamespaceMapping(containerInfo *ContainerInfo) {
	if containerSet, exists := apc.namespaceContainers.Load(containerInfo.Namespace); exists {
		containerSet.Remove(containerInfo.ContainerID)
		if containerSet.Cardinality() == 0 {
			apc.namespaceContainers.Delete(containerInfo.Namespace)
		}
	}
}

// cleanupContainerResources removes container-specific resources
func (apc *ApplicationProfileCache) cleanupContainerResources(containerID string) {
	apc.containerInfo.Delete(containerID)
	apc.callStackIndices.Delete(containerID)
}

// cleanupUnusedWorkload removes workload data if no containers are using it
func (apc *ApplicationProfileCache) cleanupUnusedWorkload(workloadID string) {
	if apc.isWorkloadStillInUse(workloadID) {
		return
	}

	if profile, exists := apc.workloadProfiles.Load(workloadID); exists {
		profileKey := apc.createProfileKey(profile.Namespace, profile.Name)
		apc.userProfileIdentifiers.Delete(profileKey)
	}

	apc.workloadStates.Delete(workloadID)
	apc.workloadProfiles.Delete(workloadID)

	logger.L().Debug("deleted workloadID from cache", helpers.String("workloadID", workloadID))
}

// isWorkloadStillInUse checks if any container is still using the workload
func (apc *ApplicationProfileCache) isWorkloadStillInUse(workloadID string) bool {
	workloadInUse := false
	apc.containerInfo.Range(func(_ string, info *ContainerInfo) bool {
		if info.WorkloadID == workloadID {
			workloadInUse = true
			return false // Stop iteration
		}
		return true
	})
	return workloadInUse
}

// waitForSharedData waits for shared container data with exponential backoff
func (apc *ApplicationProfileCache) waitForSharedData(containerID string) (*utils.WatchedContainerData, error) {
	return backoff.Retry(context.Background(), func() (*utils.WatchedContainerData, error) {
		if sharedData := apc.k8sObjectCache.GetSharedContainerData(containerID); sharedData != nil {
			return sharedData, nil
		}
		return nil, fmt.Errorf("container %s not found in shared data", containerID)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

// Utility methods

func (apc *ApplicationProfileCache) createProfileKey(namespace, name string) ProfileKey {
	return ProfileKey(fmt.Sprintf("%s/%s", namespace, name))
}

func (apc *ApplicationProfileCache) isUserManagedProfile(profile *v1beta1.ApplicationProfile) bool {
	return profile.Annotations != nil &&
		profile.Annotations[helpersv1.ManagedByMetadataKey] == helpersv1.ManagedByUserValue &&
		strings.HasPrefix(profile.GetName(), helpersv1.UserApplicationProfilePrefix)
}

// mergeProfiles combines a base profile with a user-managed profile
func (apc *ApplicationProfileCache) mergeProfiles(base, userManaged *v1beta1.ApplicationProfile) *v1beta1.ApplicationProfile {
	merged := base.DeepCopy()

	merged.Spec.Containers = apc.mergeContainerSpecs(merged.Spec.Containers, userManaged.Spec.Containers)
	merged.Spec.InitContainers = apc.mergeContainerSpecs(merged.Spec.InitContainers, userManaged.Spec.InitContainers)
	merged.Spec.EphemeralContainers = apc.mergeContainerSpecs(merged.Spec.EphemeralContainers, userManaged.Spec.EphemeralContainers)

	return merged
}

// mergeContainerSpecs merges container specifications
func (apc *ApplicationProfileCache) mergeContainerSpecs(base, userManaged []v1beta1.ApplicationProfileContainer) []v1beta1.ApplicationProfileContainer {
	if len(userManaged) != len(base) {
		logger.L().Warning("failed to merge user-managed profile with base profile",
			helpers.Int("baseContainers", len(base)),
			helpers.Int("userManagedContainers", len(userManaged)),
			helpers.String("reason", "container count mismatch"))
		return base
	}

	for i := range base {
		for j := range userManaged {
			if base[i].Name == userManaged[j].Name {
				apc.mergeContainerData(&base[i], &userManaged[j])
				break
			}
		}
	}
	return base
}

// mergeContainerData merges individual container data
func (apc *ApplicationProfileCache) mergeContainerData(base, userManaged *v1beta1.ApplicationProfileContainer) {
	base.Capabilities = append(base.Capabilities, userManaged.Capabilities...)
	base.Execs = append(base.Execs, userManaged.Execs...)
	base.Opens = append(base.Opens, userManaged.Opens...)
	base.Syscalls = append(base.Syscalls, userManaged.Syscalls...)
	base.Endpoints = append(base.Endpoints, userManaged.Endpoints...)

	// Merge policies
	for ruleID, policy := range userManaged.PolicyByRuleId {
		if existingPolicy, exists := base.PolicyByRuleId[ruleID]; exists {
			base.PolicyByRuleId[ruleID] = utils.MergePolicies(existingPolicy, policy)
		} else {
			base.PolicyByRuleId[ruleID] = policy
		}
	}
}

// Public API methods

// GetApplicationProfile retrieves the application profile for a container
func (apc *ApplicationProfileCache) GetApplicationProfile(containerID string) *v1beta1.ApplicationProfile {
	containerInfo, exists := apc.containerInfo.Load(containerID)
	if !exists || containerInfo.WorkloadID == "" {
		return nil
	}

	if profile, exists := apc.workloadProfiles.Load(containerInfo.WorkloadID); exists {
		return profile
	}
	return nil
}

// GetApplicationProfileState retrieves the profile state for a container
func (apc *ApplicationProfileCache) GetApplicationProfileState(containerID string) *objectcache.ProfileState {
	containerInfo, exists := apc.containerInfo.Load(containerID)
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

	if profileState, exists := apc.workloadStates.Load(containerInfo.WorkloadID); exists {
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

// GetCallStackSearchTree retrieves the call stack search tree for a container
func (apc *ApplicationProfileCache) GetCallStackSearchTree(containerID string) *callstackcache.CallStackSearchTree {
	if index, exists := apc.callStackIndices.Load(containerID); exists {
		return index.searchTree
	}
	return nil
}

// Ensure ApplicationProfileCache implements the required interface
var _ objectcache.ApplicationProfileCache = (*ApplicationProfileCache)(nil)
