package applicationprofilecache

import (
	"context"
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
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
	containerToSlug  maps.SafeMap[string, string]                      // cache the containerID to slug mapping, this will enable a quick lookup of the application profile
	slugToAppProfile maps.SafeMap[string, *v1beta1.ApplicationProfile] // cache the application profile
	slugToContainers maps.SafeMap[string, mapset.Set[string]]          // cache the containerIDs that belong to the application profile, this will enable removing from cache AP without pods
	slugToState      maps.SafeMap[string, applicationProfileState]     // cache the containerID to slug mapping, this will enable a quick lookup of the application profile
	k8sClient        k8sclient.K8sClientInterface
	allProfiles      mapset.Set[string] // cache all the application profiles that are ready. this will enable removing from cache AP without pods that are running on the same node
	nodeName         string
}

func NewApplicationProfileCache(nodeName string, k8sClient k8sclient.K8sClientInterface) *ApplicationProfileCacheImpl {
	return &ApplicationProfileCacheImpl{
		nodeName:         nodeName,
		k8sClient:        k8sClient,
		containerToSlug:  maps.SafeMap[string, string]{},
		slugToContainers: maps.SafeMap[string, mapset.Set[string]]{},
		allProfiles:      mapset.NewSet[string](),
	}

}

// ------------------ objectcache.ApplicationProfileCache methods -----------------------

func (ap *ApplicationProfileCacheImpl) GetApplicationProfile(containerID string) *v1beta1.ApplicationProfile {
	if s := ap.containerToSlug.Get(containerID); s != "" {
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

func (ap *ApplicationProfileCacheImpl) AddHandler(ctx context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		ap.addPod(obj)
	case "ApplicationProfile":
		ap.addApplicationProfile(ctx, obj)
	}
}
func (ap *ApplicationProfileCacheImpl) ModifyHandler(ctx context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		ap.addPod(obj)
	case "ApplicationProfile":
		ap.addApplicationProfile(ctx, obj)
	}
}
func (ap *ApplicationProfileCacheImpl) DeleteHandler(_ context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		ap.deletePod(obj)
	case "ApplicationProfile":
		ap.deleteApplicationProfile(obj)
	}
}

// ------------------ watch pod methods -----------------------

func (ap *ApplicationProfileCacheImpl) addPod(podU *unstructured.Unstructured) {

	slug, err := getSlug(podU)
	if err != nil {
		logger.L().Error("ApplicationProfileCacheImpl: failed to get slug", helpers.String("namespace", podU.GetNamespace()), helpers.String("pod", podU.GetName()), helpers.Error(err))
		return
	}

	uniqueSlug := objectcache.UniqueName(podU.GetNamespace(), slug)

	pod, err := objectcache.UnstructuredToPod(podU)
	if err != nil {
		logger.L().Error("ApplicationProfileCacheImpl: failed to unmarshal pod", helpers.String("namespace", podU.GetNamespace()), helpers.String("pod", podU.GetName()), helpers.Error(err))
		return
	}

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
			appProfile, err := ap.getApplicationProfile(podU.GetNamespace(), slug)
			if err != nil {
				logger.L().Error("failed to get application profile", helpers.Error(err))
				continue
			}

			ap.slugToAppProfile.Set(uniqueSlug, appProfile)
		}

	}

}

func (ap *ApplicationProfileCacheImpl) deletePod(obj *unstructured.Unstructured) {

	pod, err := objectcache.UnstructuredToPod(obj)
	if err != nil {
		logger.L().Error("ApplicationProfileCacheImpl: failed to unmarshal pod", helpers.String("namespace", obj.GetNamespace()), helpers.String("pod", obj.GetName()), helpers.Error(err))
		return
	}

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
func (ap *ApplicationProfileCacheImpl) addApplicationProfile(_ context.Context, obj *unstructured.Unstructured) {
	apName := objectcache.UnstructuredUniqueName(obj)

	appProfile, err := unstructuredToApplicationProfile(obj)
	if err != nil {
		logger.L().Error("failed to unmarshal application profile", helpers.String("name", apName), helpers.Error(err))
		return
	}
	apState := newApplicationProfileState(appProfile)
	ap.slugToState.Set(apName, apState)

	// the cache holds only completed application profiles.
	// check if the application profile is completed
	// if status was completed and now is not (e.g. mode changed from complete to partial), remove from cache
	if apState.status != helpersv1.Completed {
		if ap.slugToAppProfile.Has(apName) {
			ap.slugToAppProfile.Delete(apName)
			ap.allProfiles.Remove(apName)
		}
		return
	}

	// add to the cache
	ap.allProfiles.Add(apName)

	if ap.slugToContainers.Has(apName) {
		// get the full application profile from the storage
		// the watch only returns the metadata
		fullAP, err := ap.getApplicationProfile(appProfile.GetNamespace(), appProfile.GetName())
		if err != nil {
			logger.L().Error("failed to get full application profile", helpers.Error(err))
			return
		}
		ap.slugToAppProfile.Set(apName, fullAP)
		for _, i := range ap.slugToContainers.Get(apName).ToSlice() {
			ap.containerToSlug.Set(i, apName)
		}

		logger.L().Debug("added pod to application profile cache", helpers.String("name", apName))
	}
}

func (ap *ApplicationProfileCacheImpl) deleteApplicationProfile(obj *unstructured.Unstructured) {
	apName := objectcache.UnstructuredUniqueName(obj)
	ap.slugToAppProfile.Delete(apName)
	ap.slugToState.Delete(apName)
	ap.allProfiles.Remove(apName)

	logger.L().Info("deleted application profile from cache", helpers.String("uniqueSlug", apName))
}

func (ap *ApplicationProfileCacheImpl) getApplicationProfile(namespace, name string) (*v1beta1.ApplicationProfile, error) {

	u, err := ap.k8sClient.GetDynamicClient().Resource(groupVersionResource).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return unstructuredToApplicationProfile(u)
}

func unstructuredToApplicationProfile(obj *unstructured.Unstructured) (*v1beta1.ApplicationProfile, error) {

	ap := &v1beta1.ApplicationProfile{}
	err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, ap)
	if err != nil {
		return nil, err
	}

	return ap, nil
}

func getSlug(p *unstructured.Unstructured) (string, error) {
	pod := workloadinterface.NewWorkloadObj(p.Object)
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
	slug, err := names.InstanceIDToSlug(instanceID.GetName(), instanceID.GetKind(), "", instanceID.GetHashed())
	if err != nil {
		return "", fmt.Errorf("failed to get slug")
	}
	return slug, nil

}
