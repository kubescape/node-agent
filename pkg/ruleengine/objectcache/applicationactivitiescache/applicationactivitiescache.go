package applicationactivitiescache

import (
	"context"
	"encoding/json"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/ruleengine/objectcache"
	"node-agent/pkg/watcher"

	mapset "github.com/deckarep/golang-set/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var _ objectcache.ApplicationActivityCache = (*ApplicationActivityCacheImpl)(nil)
var _ watcher.Adaptor = (*ApplicationActivityCacheImpl)(nil)

type ApplicationActivityCacheImpl struct {
	nodeName         string
	k8sClient        k8sclient.K8sClientInterface
	podToSlug        maps.SafeMap[string, string]                       // cache the pod to slug mapping, this will enable a quick lookup of the application activities
	slugToAppProfile maps.SafeMap[string, *v1beta1.ApplicationActivity] // cache the application activities
	slugToPods       maps.SafeMap[string, mapset.Set[string]]           // cache the pods that belong to the application activities, this will enable removing from cache AP without pods
	allProfiles      mapset.Set[string]                                 // cache all the application activities that are ready. this will enable removing from cache AP without pods that are running on the same node
}

func NewApplicationActivityCache(nodeName string, k8sClient k8sclient.K8sClientInterface) *ApplicationActivityCacheImpl {
	return &ApplicationActivityCacheImpl{
		nodeName:    nodeName,
		k8sClient:   k8sClient,
		podToSlug:   maps.SafeMap[string, string]{},
		slugToPods:  maps.SafeMap[string, mapset.Set[string]]{},
		allProfiles: mapset.NewSet[string](),
	}

}

// ------------------ objectcache.ApplicationActivityCache methods -----------------------

func (ap *ApplicationActivityCacheImpl) GetApplicationActivity(namespace, name string) *v1beta1.ApplicationActivity {
	uniqueName := objectcache.UniqueName(namespace, name)
	if ap.slugToAppProfile.Has(uniqueName) {
		return ap.slugToAppProfile.Get(uniqueName)
	}
	return nil
}

// ------------------ watcher.Adaptor methods -----------------------

// ------------------ watcher.WatchResources methods -----------------------

func (ap *ApplicationActivityCacheImpl) WatchResources() []watcher.WatchResource {
	w := []watcher.WatchResource{}

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

	// add application activities
	apl := watcher.NewWatchResource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1beta1",
		Resource: "applicationactivities",
	}, metav1.ListOptions{})
	w = append(w, apl)

	return w
}

// ------------------ watcher.Watcher methods -----------------------
func (ap *ApplicationActivityCacheImpl) AddHandler(ctx context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		ap.addPod(obj)
	case "ApplicationActivity":
		ap.addApplicationActivity(ctx, obj)
	}
}
func (ap *ApplicationActivityCacheImpl) ModifyHandler(ctx context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		// do nothing
	case "ApplicationActivity":
		ap.addApplicationActivity(ctx, obj)
	}
}
func (ap *ApplicationActivityCacheImpl) DeleteHandler(_ context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		ap.deletePod(obj)
	case "ApplicationActivity":
		ap.deleteApplicationActivity(obj)
	}
}

// ------------------ watch pod methods -----------------------

func (ap *ApplicationActivityCacheImpl) addPod(podU *unstructured.Unstructured) {
	podName := objectcache.UnstructuredUniqueName(podU)

	if ap.podToSlug.Has(podName) {
		return
	}
	podB, err := podU.MarshalJSON()
	if err != nil {
		return
	}

	pod, err := workloadinterface.NewWorkload(podB)
	if err != nil {
		return
	}

	// get instanceIDs
	instanceIDs, err := instanceidhandler.GenerateInstanceID(pod)
	if err != nil {
		return
	}
	if len(instanceIDs) == 0 {
		return
	}

	// a single pod can have multiple instanceIDs (because of the containers), but we only need one
	instanceID := instanceIDs[0]
	slug, err := names.InstanceIDToSlug(instanceID.GetName(), instanceID.GetKind(), "", instanceID.GetHashed())
	if err != nil {
		return
	}
	uniqueSlug := objectcache.UniqueName(pod.GetNamespace(), slug)
	ap.podToSlug.Set(podName, uniqueSlug)

	if !ap.slugToPods.Has(uniqueSlug) {
		ap.slugToPods.Set(uniqueSlug, mapset.NewSet[string]())
	}
	ap.slugToPods.Get(uniqueSlug).Add(podName)

	// if application activities exists but is not cached
	if ap.allProfiles.Contains(uniqueSlug) && !ap.slugToAppProfile.Has(uniqueSlug) {

		// get the application activities
		appProfile, err := ap.getApplicationActivity(pod.GetNamespace(), slug)
		if err != nil {
			logger.L().Error("failed to get application activities", helpers.Error(err))
			return
		}
		ap.slugToAppProfile.Set(uniqueSlug, appProfile)
	}
}

func (ap *ApplicationActivityCacheImpl) deletePod(obj *unstructured.Unstructured) {
	podName := objectcache.UnstructuredUniqueName(obj)
	uniqueSlug := ap.podToSlug.Get(podName)
	ap.podToSlug.Delete(podName)

	// remove pod form the application activities mapping
	if ap.slugToPods.Has(uniqueSlug) {
		ap.slugToPods.Get(uniqueSlug).Remove(podName)
		if ap.slugToPods.Get(uniqueSlug).Cardinality() == 0 {
			ap.slugToPods.Delete(uniqueSlug)
			// remove full application activities from cache
			ap.slugToAppProfile.Delete(uniqueSlug)
		}
	}
}

// ------------------ watch application activities methods -----------------------
func (ap *ApplicationActivityCacheImpl) addApplicationActivity(_ context.Context, obj *unstructured.Unstructured) {
	apName := objectcache.UnstructuredUniqueName(obj)

	appProfile, err := unstructuredToApplicationActivity(obj)
	if err != nil {
		logger.L().Error("failed to unmarshal application activities", helpers.Error(err))
		return
	}

	// check if the application activities is ready
	// TODO: @amir
	// if was ready and now is not, remove from cache
	// if ap.slugToAppProfile.Has(apName) {
	// 	return
	// }

	// get the full application activities from the storage
	// the watch only returns the metadata
	fullAP, err := ap.getApplicationActivity(appProfile.GetNamespace(), appProfile.GetName())
	if err != nil {
		logger.L().Error("failed to get full application activities", helpers.Error(err))
		return
	}

	ap.slugToAppProfile.Set(apName, fullAP)
	ap.allProfiles.Add(apName)
	ap.podToSlug.Range(func(podName, uniqueSlug string) bool {
		if uniqueSlug == apName {
			if !ap.slugToPods.Has(uniqueSlug) {
				ap.slugToPods.Set(uniqueSlug, mapset.NewSet[string]())
			}
			ap.slugToPods.Get(uniqueSlug).Add(podName)
		}
		return true
	})
}

func (ap *ApplicationActivityCacheImpl) deleteApplicationActivity(obj *unstructured.Unstructured) {
	apName := objectcache.UnstructuredUniqueName(obj)
	ap.slugToAppProfile.Delete(apName)
	ap.allProfiles.Remove(apName)
	ap.slugToPods.Delete(apName)
}

func unstructuredToApplicationActivity(obj *unstructured.Unstructured) (*v1beta1.ApplicationActivity, error) {
	bytes, err := obj.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var ap *v1beta1.ApplicationActivity
	err = json.Unmarshal(bytes, ap)
	if err != nil {
		return nil, err
	}
	return ap, nil
}
func (ap *ApplicationActivityCacheImpl) getApplicationActivity(namespace, name string) (*v1beta1.ApplicationActivity, error) {
	gvr := schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1beta1",
		Resource: "applicationactivities",
	}
	u, err := ap.k8sClient.GetDynamicClient().Resource(gvr).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return unstructuredToApplicationActivity(u)
}
