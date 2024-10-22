package applicationprofilecache

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	versioned "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

type ApplicationProfileCacheImpl struct {
	containerToSlug      maps.SafeMap[string, string]                      // cache the containerID to slug mapping, this will enable a quick lookup of the application profile
	slugToAppProfile     maps.SafeMap[string, *v1beta1.ApplicationProfile] // cache the application profile
	slugToContainers     maps.SafeMap[string, mapset.Set[string]]          // cache the containerIDs that belong to the application profile, this will enable removing from cache AP without pods
	slugToState          maps.SafeMap[string, applicationProfileState]     // cache the containerID to slug mapping, this will enable a quick lookup of the application profile
	storageClient        versioned.SpdxV1beta1Interface
	allProfiles          mapset.Set[string] // cache all the application profiles that are ready. this will enable removing from cache AP without pods that are running on the same node
	nodeName             string
	maxDelaySeconds      int // maximum delay in seconds before getting the full object from the storage
	userManagedProfiles  maps.SafeMap[string, *v1beta1.ApplicationProfile]
	pendingMergeProfiles maps.SafeMap[string, *v1beta1.ApplicationProfile]
	mergeWaitGroup       sync.WaitGroup
	mergeTimeout         time.Duration
	testMode             bool
}

type CacheOption func(*ApplicationProfileCacheImpl)

// Option to enable test mode
func WithTestMode() CacheOption {
	return func(a *ApplicationProfileCacheImpl) {
		a.testMode = true
	}
}

func NewApplicationProfileCache(nodeName string, storageClient versioned.SpdxV1beta1Interface, maxDelaySeconds int, opts ...CacheOption) *ApplicationProfileCacheImpl {
	cache := &ApplicationProfileCacheImpl{
		nodeName:             nodeName,
		maxDelaySeconds:      maxDelaySeconds,
		storageClient:        storageClient,
		containerToSlug:      maps.SafeMap[string, string]{},
		slugToAppProfile:     maps.SafeMap[string, *v1beta1.ApplicationProfile]{},
		slugToContainers:     maps.SafeMap[string, mapset.Set[string]]{},
		slugToState:          maps.SafeMap[string, applicationProfileState]{},
		allProfiles:          mapset.NewSet[string](),
		userManagedProfiles:  maps.SafeMap[string, *v1beta1.ApplicationProfile]{},
		pendingMergeProfiles: maps.SafeMap[string, *v1beta1.ApplicationProfile]{},
		mergeTimeout:         time.Minute * 1,
		testMode:             false,
	}

	// Apply options
	for _, opt := range opts {
		opt(cache)
	}

	return cache
}

// ------------------ objectcache.ApplicationProfileCache methods -----------------------

func (ap *ApplicationProfileCacheImpl) handleUserManagedProfile(ctx context.Context, appProfile *v1beta1.ApplicationProfile, apName string) {
	// Store the user-managed profile
	ap.userManagedProfiles.Set(apName, appProfile)

	// Get the corresponding base profile name
	baseProfileName := getBaseProfileName(appProfile.GetName())
	baseProfileUniqueName := objectcache.UniqueName(appProfile.GetNamespace(), baseProfileName)

	// Clear existing cached base profile if it exists
	ap.slugToAppProfile.Delete(baseProfileUniqueName)

	// Fetch fresh base profile from cluster
	baseProfile, err := ap.getApplicationProfile(appProfile.GetNamespace(), baseProfileName)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			logger.L().Error("failed to get base application profile",
				helpers.String("name", baseProfileName),
				helpers.String("namespace", appProfile.GetNamespace()),
				helpers.Error(err))
		}
		// Store user-managed profile in pending merge map and wait for base profile
		ap.pendingMergeProfiles.Set(baseProfileUniqueName, appProfile)
		ap.waitForNormalProfile(ctx, baseProfileUniqueName)
		return
	}

	// Merge and cache the result
	ap.mergeProfiles(baseProfile, appProfile)
}

func (ap *ApplicationProfileCacheImpl) handleNormalProfile(appProfile *v1beta1.ApplicationProfile, apName string) {
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

	// Check for corresponding user-managed profile with ug- prefix
	userManagedName := "ug-" + appProfile.GetName()
	userManagedUniqueName := objectcache.UniqueName(appProfile.GetNamespace(), userManagedName)

	if userManagedProfile := ap.userManagedProfiles.Get(userManagedUniqueName); userManagedProfile != nil {
		if ap.testMode {
			fullProfile, err := ap.getApplicationProfile(appProfile.GetNamespace(), appProfile.GetName())
			if err != nil {
				logger.L().Error("failed to get full application profile", helpers.Error(err))
				return
			}
			ap.mergeProfiles(fullProfile, userManagedProfile)
		} else {
			time.AfterFunc(utils.RandomDuration(ap.maxDelaySeconds, time.Second), func() {
				fullProfile, err := ap.getApplicationProfile(appProfile.GetNamespace(), appProfile.GetName())
				if err != nil {
					logger.L().Error("failed to get full application profile", helpers.Error(err))
					return
				}
				ap.mergeProfiles(fullProfile, userManagedProfile)
			})
		}
	} else if pendingProfile := ap.pendingMergeProfiles.Get(apName); pendingProfile != nil {
		if ap.testMode {
			fullProfile, err := ap.getApplicationProfile(appProfile.GetNamespace(), appProfile.GetName())
			if err != nil {
				logger.L().Error("failed to get full application profile", helpers.Error(err))
				return
			}
			ap.mergeProfiles(fullProfile, pendingProfile)
			ap.pendingMergeProfiles.Delete(apName)
		} else {
			time.AfterFunc(utils.RandomDuration(ap.maxDelaySeconds, time.Second), func() {
				fullProfile, err := ap.getApplicationProfile(appProfile.GetNamespace(), appProfile.GetName())
				if err != nil {
					logger.L().Error("failed to get full application profile", helpers.Error(err))
					return
				}
				ap.mergeProfiles(fullProfile, pendingProfile)
				ap.pendingMergeProfiles.Delete(apName)
			})
		}
	} else {
		if ap.slugToContainers.Has(apName) {
			if ap.testMode {
				fullProfile, err := ap.getApplicationProfile(appProfile.GetNamespace(), appProfile.GetName())
				if err != nil {
					logger.L().Error("failed to get full application profile", helpers.Error(err))
					return
				}
				ap.slugToAppProfile.Set(apName, fullProfile)
				for _, containerID := range ap.slugToContainers.Get(apName).ToSlice() {
					ap.containerToSlug.Set(containerID, apName)
				}
			} else {
				time.AfterFunc(utils.RandomDuration(ap.maxDelaySeconds, time.Second), func() {
					ap.addFullApplicationProfile(appProfile, apName)
				})
			}
		}
	}
}

func (ap *ApplicationProfileCacheImpl) addApplicationProfile(ctx context.Context, obj runtime.Object) {
	appProfile := obj.(*v1beta1.ApplicationProfile)
	apName := objectcache.MetaUniqueName(appProfile)

	isUserManaged := appProfile.Annotations != nil &&
		appProfile.Annotations["kubescape.io/managed-by"] == "User" &&
		isUserManagedByPrefix(appProfile.GetName())

	if isUserManaged {
		ap.handleUserManagedProfile(ctx, appProfile, apName)
	} else {
		ap.handleNormalProfile(appProfile, apName)
	}
}

func (ap *ApplicationProfileCacheImpl) GetApplicationProfile(containerID string) *v1beta1.ApplicationProfile {
	if s := ap.containerToSlug.Get(containerID); s != "" {
		// Check if there's a user-managed version first
		userManagedSlug := "ug-" + s
		if profile := ap.slugToAppProfile.Get(userManagedSlug); profile != nil {
			return profile
		}
		return ap.slugToAppProfile.Get(s)
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
		ap.addApplicationProfile(ctx, appProfile)
	}
}

func (ap *ApplicationProfileCacheImpl) ModifyHandler(ctx context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		ap.addPod(pod)
	} else if appProfile, ok := obj.(*v1beta1.ApplicationProfile); ok {
		ap.addApplicationProfile(ctx, appProfile)
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
		logger.L().Error("ApplicationProfileCacheImpl: failed to get slug", helpers.String("namespace", pod.GetNamespace()), helpers.String("pod", pod.GetName()), helpers.Error(err))
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
				logger.L().Error("failed to get application profile", helpers.Error(err))
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

	// remove pod form the application profile mapping
	if ap.slugToContainers.Has(uniqueSlug) {
		ap.slugToContainers.Get(uniqueSlug).Remove(containerID)
		if ap.slugToContainers.Get(uniqueSlug).Cardinality() == 0 {
			// remove full application profile from cache
			ap.slugToContainers.Delete(uniqueSlug)
			ap.allProfiles.Remove(uniqueSlug)
			ap.slugToAppProfile.Delete(uniqueSlug)
			logger.L().Debug("deleted pod from application profile cache", helpers.String("containerID", containerID), helpers.String("uniqueSlug", uniqueSlug))
		}
	}
}

// ------------------ watch application profile methods -----------------------

func (ap *ApplicationProfileCacheImpl) addFullApplicationProfile(appProfile *v1beta1.ApplicationProfile, apName string) {
	fullAP, err := ap.getApplicationProfile(appProfile.GetNamespace(), appProfile.GetName())
	if err != nil {
		logger.L().Error("failed to get full application profile", helpers.Error(err))
		return
	}

	if ap.slugToContainers.Has(apName) {
		ap.slugToAppProfile.Set(apName, fullAP)
		for _, containerID := range ap.slugToContainers.Get(apName).ToSlice() {
			ap.containerToSlug.Set(containerID, apName)
		}
		logger.L().Debug("added pod to application profile cache", helpers.String("name", apName))
	}
}

func (ap *ApplicationProfileCacheImpl) mergeProfiles(normalProfile, userManagedProfile *v1beta1.ApplicationProfile) {
	mergedProfile := ap.performMerge(normalProfile, userManagedProfile)
	ap.slugToAppProfile.Set(objectcache.MetaUniqueName(mergedProfile), mergedProfile)

	if ap.slugToContainers.Has(objectcache.MetaUniqueName(mergedProfile)) {
		for _, containerID := range ap.slugToContainers.Get(objectcache.MetaUniqueName(mergedProfile)).ToSlice() {
			ap.containerToSlug.Set(containerID, objectcache.MetaUniqueName(mergedProfile))
		}
	}

	logger.L().Debug("Merged user-managed profile with normal profile",
		helpers.String("name", mergedProfile.GetName()),
		helpers.String("namespace", mergedProfile.GetNamespace()))
}

func (ap *ApplicationProfileCacheImpl) performMerge(normalProfile, userManagedProfile *v1beta1.ApplicationProfile) *v1beta1.ApplicationProfile {
	mergedProfile := normalProfile.DeepCopy()

	// Merge spec
	mergedProfile.Spec.Containers = ap.mergeContainers(mergedProfile.Spec.Containers, userManagedProfile.Spec.Containers)
	mergedProfile.Spec.InitContainers = ap.mergeContainers(mergedProfile.Spec.InitContainers, userManagedProfile.Spec.InitContainers)
	mergedProfile.Spec.EphemeralContainers = ap.mergeContainers(mergedProfile.Spec.EphemeralContainers, userManagedProfile.Spec.EphemeralContainers)

	// Remove the user-managed annotation
	delete(mergedProfile.Annotations, "kubescape.io/managed-by")

	return mergedProfile
}

func (ap *ApplicationProfileCacheImpl) mergeContainers(normalContainers, userManagedContainers []v1beta1.ApplicationProfileContainer) []v1beta1.ApplicationProfileContainer {
	containerMap := make(map[string]*v1beta1.ApplicationProfileContainer)

	for i := range normalContainers {
		containerMap[normalContainers[i].Name] = &normalContainers[i]
	}

	for _, userContainer := range userManagedContainers {
		if normalContainer, exists := containerMap[userContainer.Name]; exists {
			ap.mergeContainer(normalContainer, &userContainer)
		} else {
			normalContainers = append(normalContainers, userContainer)
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
}

func (ap *ApplicationProfileCacheImpl) waitForNormalProfile(ctx context.Context, apName string) {
	ap.mergeWaitGroup.Add(1)
	go func() {
		defer ap.mergeWaitGroup.Done()
		timer := time.NewTimer(ap.mergeTimeout)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				logger.L().Warning("Timeout waiting for normal profile", helpers.String("name", apName))
				ap.pendingMergeProfiles.Delete(apName)
				return
			default:
				if normalProfile := ap.slugToAppProfile.Get(apName); normalProfile != nil {
					userManagedProfile := ap.pendingMergeProfiles.Get(apName)
					ap.mergeProfiles(normalProfile, userManagedProfile)
					ap.pendingMergeProfiles.Delete(apName)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

func (ap *ApplicationProfileCacheImpl) deleteApplicationProfile(obj runtime.Object) {
	apName := objectcache.MetaUniqueName(obj.(metav1.Object))
	ap.slugToAppProfile.Delete(apName)
	ap.slugToState.Delete(apName)
	ap.allProfiles.Remove(apName)

	logger.L().Info("deleted application profile from cache", helpers.String("uniqueSlug", apName))
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

// Helper function to check if a profile name is user-managed by prefix
func isUserManagedByPrefix(name string) bool {
	return strings.HasPrefix(name, "ug-")
}

// Helper function to get base profile name from user-managed profile name
func getBaseProfileName(userManagedName string) string {
	return strings.TrimPrefix(userManagedName, "ug-")
}
