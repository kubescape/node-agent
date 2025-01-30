package applicationprofilecache

import (
	"context"
	"fmt"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/applicationprofilecache/callstackcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	versioned "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var groupVersionResource = schema.GroupVersionResource{
	Group:    "spdx.softwarecomposition.kubescape.io",
	Version:  "v1beta1",
	Resource: "applicationprofiles",
}

var _ objectcache.ApplicationProfileCache = (*ApplicationProfileCacheImpl)(nil)
var _ watcher.Adaptor = (*ApplicationProfileCacheImpl)(nil)

type applicationProfileState struct {
	status string
	mode   string
}

func newApplicationProfileState(ap *v1beta1.ApplicationProfile) applicationProfileState {
	mode := ap.Annotations[helpersv1.CompletionMetadataKey]
	status := ap.Annotations[helpersv1.StatusMetadataKey]
	return applicationProfileState{
		status: status,
		mode:   mode,
	}
}

// ContainerCallStackIndex maintains call stack search trees for a container
type ContainerCallStackIndex struct {
	searchTree *callstackcache.CallStackSearchTree
}

type ApplicationProfileCacheImpl struct {
	containerToSlug     maps.SafeMap[string, string]                      // cache the containerID to slug mapping, this will enable a quick lookup of the application profile
	slugToAppProfile    maps.SafeMap[string, *v1beta1.ApplicationProfile] // cache the application profile
	slugToContainers    maps.SafeMap[string, mapset.Set[string]]          // cache the containerIDs that belong to the application profile, this will enable removing from cache AP without pods
	slugToState         maps.SafeMap[string, applicationProfileState]     // cache the containerID to slug mapping, this will enable a quick lookup of the application profile
	storageClient       versioned.SpdxV1beta1Interface
	allProfiles         mapset.Set[string] // cache all the application profiles that are ready. this will enable removing from cache AP without pods that are running on the same node
	nodeName            string
	maxDelaySeconds     int // maximum delay in seconds before getting the full object from the storage
	userManagedProfiles maps.SafeMap[string, *v1beta1.ApplicationProfile]
	containerCallStacks maps.SafeMap[string, *ContainerCallStackIndex] // cache the containerID to call stack search tree mapping
}

func NewApplicationProfileCache(nodeName string, storageClient versioned.SpdxV1beta1Interface, maxDelaySeconds int) *ApplicationProfileCacheImpl {
	return &ApplicationProfileCacheImpl{
		nodeName:            nodeName,
		maxDelaySeconds:     maxDelaySeconds,
		storageClient:       storageClient,
		containerToSlug:     maps.SafeMap[string, string]{},
		slugToAppProfile:    maps.SafeMap[string, *v1beta1.ApplicationProfile]{},
		slugToContainers:    maps.SafeMap[string, mapset.Set[string]]{},
		slugToState:         maps.SafeMap[string, applicationProfileState]{},
		allProfiles:         mapset.NewSet[string](),
		userManagedProfiles: maps.SafeMap[string, *v1beta1.ApplicationProfile]{},
		containerCallStacks: maps.SafeMap[string, *ContainerCallStackIndex]{},
	}
}

// ------------------ objectcache.ApplicationProfileCache methods -----------------------

func (ap *ApplicationProfileCacheImpl) handleUserManagedProfile(appProfile *v1beta1.ApplicationProfile) {
	baseProfileName := strings.TrimPrefix(appProfile.GetName(), "ug-")
	baseProfileUniqueName := objectcache.UniqueName(appProfile.GetNamespace(), baseProfileName)

	// Get the full user managed profile from the storage
	userManagedProfile, err := ap.getApplicationProfile(appProfile.GetNamespace(), appProfile.GetName())
	if err != nil {
		logger.L().Warning("ApplicationProfileCacheImpl - failed to get full application profile", helpers.Error(err))
		return
	}

	// Store the user-managed profile temporarily
	ap.userManagedProfiles.Set(baseProfileUniqueName, userManagedProfile)

	// If we have the base profile cached, fetch a fresh copy and merge.
	// If the base profile is not cached yet, the merge will be attempted when it's added.
	if ap.slugToAppProfile.Has(baseProfileUniqueName) {
		// Fetch fresh base profile from cluster
		freshBaseProfile, err := ap.getApplicationProfile(appProfile.GetNamespace(), baseProfileName)
		if err != nil {
			logger.L().Warning("ApplicationProfileCacheImpl - failed to get fresh base profile for merging",
				helpers.String("name", baseProfileName),
				helpers.String("namespace", appProfile.GetNamespace()),
				helpers.Error(err))
			return
		}

		mergedProfile := ap.performMerge(freshBaseProfile, userManagedProfile)
		ap.slugToAppProfile.Set(baseProfileUniqueName, mergedProfile)

		// Clean up the user-managed profile after successful merge
		ap.userManagedProfiles.Delete(baseProfileUniqueName)

		logger.L().Debug("ApplicationProfileCacheImpl - merged user-managed profile with fresh base profile",
			helpers.String("name", baseProfileName),
			helpers.String("namespace", appProfile.GetNamespace()))
	}
}

// indexContainerCallStacks builds the search index for a container's call stacks and removes them from the profile
func (ap *ApplicationProfileCacheImpl) indexContainerCallStacks(containerID string, appProfile *v1beta1.ApplicationProfile) {
	// Initialize container index if needed
	if !ap.containerCallStacks.Has(containerID) {
		ap.containerCallStacks.Set(containerID, &ContainerCallStackIndex{
			searchTree: callstackcache.NewCallStackSearchTree(),
		})
	}

	index := ap.containerCallStacks.Get(containerID)

	// Find the container in the profile and index its call stacks
	for i := range appProfile.Spec.Containers {
		if appProfile.Spec.Containers[i].ImageID == containerID {
			// Index all call stacks
			for _, stack := range appProfile.Spec.Containers[i].IdentifiedCallStacks {
				index.searchTree.AddCallStack(stack)
			}

			// Clear the call stacks to free memory
			appProfile.Spec.Containers[i].IdentifiedCallStacks = nil
			break
		}
	}

	// Also check init containers
	for i := range appProfile.Spec.InitContainers {
		if appProfile.Spec.InitContainers[i].ImageID == containerID {
			for _, stack := range appProfile.Spec.InitContainers[i].IdentifiedCallStacks {
				index.searchTree.AddCallStack(stack)
			}
			appProfile.Spec.InitContainers[i].IdentifiedCallStacks = nil
			break
		}
	}

	// And ephemeral containers
	for i := range appProfile.Spec.EphemeralContainers {
		if appProfile.Spec.EphemeralContainers[i].ImageID == containerID {
			for _, stack := range appProfile.Spec.EphemeralContainers[i].IdentifiedCallStacks {
				index.searchTree.AddCallStack(stack)
			}
			appProfile.Spec.EphemeralContainers[i].IdentifiedCallStacks = nil
			break
		}
	}
}

func (ap *ApplicationProfileCacheImpl) addApplicationProfile(obj runtime.Object) {
	appProfile := obj.(*v1beta1.ApplicationProfile)
	apName := objectcache.MetaUniqueName(appProfile)

	if isUserManagedProfile(appProfile) {
		ap.handleUserManagedProfile(appProfile)
		return
	}

	// Original behavior for normal profiles
	apState := newApplicationProfileState(appProfile)
	ap.slugToState.Set(apName, apState)

	if apState.status != helpersv1.Completed {
		if ap.slugToAppProfile.Has(apName) {
			ap.slugToAppProfile.Delete(apName)
			ap.allProfiles.Remove(apName)
		}
		return
	}

	ap.allProfiles.Add(apName)

	if ap.slugToContainers.Has(apName) {
		time.AfterFunc(utils.RandomDuration(ap.maxDelaySeconds, time.Second), func() {
			ap.addFullApplicationProfile(appProfile, apName)
		})
	}
}

func (ap *ApplicationProfileCacheImpl) GetApplicationProfile(containerID string) *v1beta1.ApplicationProfile {
	if s := ap.containerToSlug.Get(containerID); s != "" {
		return ap.slugToAppProfile.Get(s)
	}
	return nil
}

func (ap *ApplicationProfileCacheImpl) GetCallStackSearchTree(containerID string) *callstackcache.CallStackSearchTree {
	if index := ap.containerCallStacks.Get(containerID); index != nil {
		return index.searchTree
	}
	return nil
}

// ------------------ watcher.Adaptor methods -----------------------

// ------------------ watcher.WatchResources methods -----------------------

func (ap *ApplicationProfileCacheImpl) WatchResources() []watcher.WatchResource {
	var w []watcher.WatchResource

	// add pod
	p := watcher.NewWatchResource(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	},
		metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + ap.nodeName,
		},
	)
	w = append(w, p)

	// add application profile
	apl := watcher.NewWatchResource(groupVersionResource, metav1.ListOptions{})
	w = append(w, apl)

	return w
}

// ------------------ watcher.Watcher methods -----------------------

func (ap *ApplicationProfileCacheImpl) AddHandler(ctx context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		ap.addPod(pod)
	} else if appProfile, ok := obj.(*v1beta1.ApplicationProfile); ok {
		ap.addApplicationProfile(appProfile)
	}
}

func (ap *ApplicationProfileCacheImpl) ModifyHandler(ctx context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		ap.addPod(pod)
	} else if appProfile, ok := obj.(*v1beta1.ApplicationProfile); ok {
		ap.addApplicationProfile(appProfile)
	}
}

func (ap *ApplicationProfileCacheImpl) DeleteHandler(_ context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		ap.deletePod(pod)
	} else if appProfile, ok := obj.(*v1beta1.ApplicationProfile); ok {
		ap.deleteApplicationProfile(appProfile)
	}
}

// ------------------ watch pod methods -----------------------

func (ap *ApplicationProfileCacheImpl) addPod(obj runtime.Object) {
	pod := obj.(*corev1.Pod)

	slug, err := getSlug(pod)
	if err != nil {
		logger.L().Warning("ApplicationProfileCacheImpl - failed to get slug", helpers.String("namespace", pod.GetNamespace()), helpers.String("pod", pod.GetName()), helpers.Error(err))
		return
	}

	uniqueSlug := objectcache.UniqueName(pod.GetNamespace(), slug)

	// in case of modified pod, remove the old containers
	terminatedContainers := objectcache.ListTerminatedContainers(pod)
	for _, container := range terminatedContainers {
		ap.removeContainer(container)
	}

	containers := objectcache.ListContainersIDs(pod)
	for _, container := range containers {

		if !ap.slugToContainers.Has(uniqueSlug) {
			ap.slugToContainers.Set(uniqueSlug, mapset.NewSet[string]())
		}
		ap.slugToContainers.Get(uniqueSlug).Add(container)

		if s := ap.slugToState.Get(uniqueSlug); s.mode != helpersv1.Complete {
			// if application profile is not complete, do not cache the pod
			continue
		}

		// add the container to the cache
		if ap.containerToSlug.Has(container) {
			continue
		}
		ap.containerToSlug.Set(container, uniqueSlug)

		// if application profile exists but is not cached
		if ap.allProfiles.Contains(uniqueSlug) && !ap.slugToAppProfile.Has(uniqueSlug) {

			// get the application profile
			appProfile, err := ap.getApplicationProfile(pod.GetNamespace(), slug)
			if err != nil {
				logger.L().Warning("ApplicationProfileCacheImpl - failed to get application profile", helpers.Error(err))
				continue
			}

			ap.slugToAppProfile.Set(uniqueSlug, appProfile)
		}

	}

}

func (ap *ApplicationProfileCacheImpl) deletePod(obj runtime.Object) {
	pod := obj.(*corev1.Pod)

	containers := objectcache.ListContainersIDs(pod)
	for _, container := range containers {
		ap.removeContainer(container)
	}
}

func (ap *ApplicationProfileCacheImpl) removeContainer(containerID string) {

	uniqueSlug := ap.containerToSlug.Get(containerID)
	ap.containerToSlug.Delete(containerID)
	ap.containerCallStacks.Delete(containerID)

	// remove pod form the application profile mapping
	if ap.slugToContainers.Has(uniqueSlug) {
		ap.slugToContainers.Get(uniqueSlug).Remove(containerID)
		if ap.slugToContainers.Get(uniqueSlug).Cardinality() == 0 {
			// remove full application profile from cache
			ap.slugToContainers.Delete(uniqueSlug)
			ap.allProfiles.Remove(uniqueSlug)
			ap.slugToAppProfile.Delete(uniqueSlug)
			logger.L().Debug("ApplicationProfileCacheImpl - deleted pod from application profile cache", helpers.String("containerID", containerID), helpers.String("uniqueSlug", uniqueSlug))
		}
	}
}

// ------------------ watch application profile methods -----------------------

func (ap *ApplicationProfileCacheImpl) addFullApplicationProfile(appProfile *v1beta1.ApplicationProfile, apName string) {
	fullAP, err := ap.getApplicationProfile(appProfile.GetNamespace(), appProfile.GetName())
	if err != nil {
		logger.L().Warning("ApplicationProfileCacheImpl - failed to get full application profile", helpers.Error(err))
		return
	}

	// Check if there's a pending user-managed profile to merge
	if ap.userManagedProfiles.Has(apName) {
		userManagedProfile := ap.userManagedProfiles.Get(apName)
		fullAP = ap.performMerge(fullAP, userManagedProfile)
		// Clean up the user-managed profile after successful merge
		ap.userManagedProfiles.Delete(apName)
		logger.L().Debug("ApplicationProfileCacheImpl - merged pending user-managed profile", helpers.String("name", apName))
	}

	ap.slugToAppProfile.Set(apName, fullAP)
	for _, i := range ap.slugToContainers.Get(apName).ToSlice() {
		ap.containerToSlug.Set(i, apName)
		ap.indexContainerCallStacks(i, fullAP)
	}
	logger.L().Debug("ApplicationProfileCacheImpl - added pod to application profile cache", helpers.String("name", apName))
}

func (ap *ApplicationProfileCacheImpl) performMerge(normalProfile, userManagedProfile *v1beta1.ApplicationProfile) *v1beta1.ApplicationProfile {
	mergedProfile := normalProfile.DeepCopy()

	// Merge spec
	mergedProfile.Spec.Containers = ap.mergeContainers(mergedProfile.Spec.Containers, userManagedProfile.Spec.Containers)
	mergedProfile.Spec.InitContainers = ap.mergeContainers(mergedProfile.Spec.InitContainers, userManagedProfile.Spec.InitContainers)
	mergedProfile.Spec.EphemeralContainers = ap.mergeContainers(mergedProfile.Spec.EphemeralContainers, userManagedProfile.Spec.EphemeralContainers)

	return mergedProfile
}

func (ap *ApplicationProfileCacheImpl) mergeContainers(normalContainers, userManagedContainers []v1beta1.ApplicationProfileContainer) []v1beta1.ApplicationProfileContainer {
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
				ap.mergeContainer(&normalContainers[i], &userContainer)
				break
			}
		}
	}
	return normalContainers
}

func (ap *ApplicationProfileCacheImpl) mergeContainer(normalContainer, userContainer *v1beta1.ApplicationProfileContainer) {
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

func (ap *ApplicationProfileCacheImpl) deleteApplicationProfile(obj runtime.Object) {
	appProfile := obj.(*v1beta1.ApplicationProfile)
	apName := objectcache.MetaUniqueName(appProfile)

	if isUserManagedProfile(appProfile) {
		// For user-managed profiles, we need to use the base name for cleanup
		baseProfileName := strings.TrimPrefix(appProfile.GetName(), "ug-")
		baseProfileUniqueName := objectcache.UniqueName(appProfile.GetNamespace(), baseProfileName)
		ap.userManagedProfiles.Delete(baseProfileUniqueName)

		logger.L().Debug("ApplicationProfileCacheImpl - deleted user-managed profile from cache",
			helpers.String("profileName", appProfile.GetName()),
			helpers.String("baseProfile", baseProfileName))
	} else {
		// For normal profiles, clean up all related data
		ap.slugToAppProfile.Delete(apName)
		ap.slugToState.Delete(apName)
		ap.allProfiles.Remove(apName)

		// Log the deletion of normal profile
		logger.L().Debug("ApplicationProfileCacheImpl - deleted application profile from cache",
			helpers.String("uniqueSlug", apName))
	}

	// Clean up any orphaned user-managed profiles
	ap.cleanupOrphanedUserManagedProfiles()
}

func (ap *ApplicationProfileCacheImpl) getApplicationProfile(namespace, name string) (*v1beta1.ApplicationProfile, error) {
	return ap.storageClient.ApplicationProfiles(namespace).Get(context.Background(), name, metav1.GetOptions{})
}

func getSlug(p *corev1.Pod) (string, error) {
	// need to set APIVersion and Kind before unstructured conversion, preparing for instanceID extraction
	p.APIVersion = "v1"
	p.Kind = "Pod"

	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&p)
	if err != nil {
		return "", fmt.Errorf("failed to convert runtime object to unstructured: %w", err)
	}
	pod := workloadinterface.NewWorkloadObj(unstructuredObj)
	if pod == nil {
		return "", fmt.Errorf("failed to get workload object")
	}

	// get instanceIDs
	instanceIDs, err := instanceidhandler.GenerateInstanceID(pod)
	if err != nil {
		return "", err
	}
	if len(instanceIDs) == 0 {
		return "", fmt.Errorf("instanceIDs is empty")
	}

	// a single pod can have multiple instanceIDs (because of the containers), but we only need one
	instanceID := instanceIDs[0]
	slug, err := instanceID.GetSlug(true)
	if err != nil {
		return "", fmt.Errorf("failed to get slug")
	}
	return slug, nil
}

// Add cleanup method for any orphaned user-managed profiles
func (ap *ApplicationProfileCacheImpl) cleanupOrphanedUserManagedProfiles() {
	// This could be called periodically or during certain operations
	ap.userManagedProfiles.Range(func(key string, value *v1beta1.ApplicationProfile) bool {
		if ap.slugToAppProfile.Has(key) {
			// If base profile exists but merge didn't happen for some reason,
			// attempt merge again and cleanup
			if baseProfile := ap.slugToAppProfile.Get(key); baseProfile != nil {
				mergedProfile := ap.performMerge(baseProfile, value)
				ap.slugToAppProfile.Set(key, mergedProfile)
				ap.userManagedProfiles.Delete(key)
				logger.L().Debug("ApplicationProfileCacheImpl - cleaned up orphaned user-managed profile", helpers.String("name", key))
			}
		}
		return true
	})
}

func isUserManagedProfile(appProfile *v1beta1.ApplicationProfile) bool {
	return appProfile.Annotations != nil &&
		appProfile.Annotations["kubescape.io/managed-by"] == "User" &&
		strings.HasPrefix(appProfile.GetName(), "ug-")
}
