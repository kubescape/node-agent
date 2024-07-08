package networkneighborhoodcache

import (
	"context"
	"fmt"

	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/watcher"

	mapset "github.com/deckarep/golang-set/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"

	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var groupVersionResource = schema.GroupVersionResource{
	Group:    "spdx.softwarecomposition.kubescape.io",
	Version:  "v1beta1",
	Resource: "networkneighborhoods",
}

var _ objectcache.NetworkNeighborhoodCache = (*NetworkNeighborhoodCacheImpl)(nil)
var _ watcher.Adaptor = (*NetworkNeighborhoodCacheImpl)(nil)

type networkNeighborhoodState struct {
	status string
	mode   string
}

func newNetworkNeighborhoodState(nn *v1beta1.NetworkNeighborhood) networkNeighborhoodState {
	mode := nn.Annotations[helpersv1.CompletionMetadataKey]
	status := nn.Annotations[helpersv1.StatusMetadataKey]
	return networkNeighborhoodState{
		status: status,
		mode:   mode,
	}
}

type NetworkNeighborhoodCacheImpl struct {
	containerToSlug           maps.SafeMap[string, string]                       // cache the containerID to slug mapping, this will enable a quick lookup of the network neighborhood
	slugToNetworkNeighborhood maps.SafeMap[string, *v1beta1.NetworkNeighborhood] // cache the network neighborhood
	slugToContainers          maps.SafeMap[string, mapset.Set[string]]           // cache the containerIDs that belong to the network neighborhood, this will enable removing from cache NN without pods
	slugToState               maps.SafeMap[string, networkNeighborhoodState]     // cache the containerID to slug mapping, this will enable a quick lookup of the network neighborhood
	k8sClient                 k8sclient.K8sClientInterface
	allNetworkNeighborhoods   mapset.Set[string] // cache all the NN that are ready. this will enable removing from cache NN without pods that are running on the same node
	nodeName                  string
}

func NewNetworkNeighborhoodCache(nodeName string, k8sClient k8sclient.K8sClientInterface) *NetworkNeighborhoodCacheImpl {
	return &NetworkNeighborhoodCacheImpl{
		nodeName:                nodeName,
		k8sClient:               k8sClient,
		containerToSlug:         maps.SafeMap[string, string]{},
		slugToContainers:        maps.SafeMap[string, mapset.Set[string]]{},
		allNetworkNeighborhoods: mapset.NewSet[string](),
	}

}

// ------------------ objectcache.NetworkNeighborhoodCache methods -----------------------

func (nn *NetworkNeighborhoodCacheImpl) GetNetworkNeighborhood(containerID string) *v1beta1.NetworkNeighborhood {
	if s := nn.containerToSlug.Get(containerID); s != "" {
		return nn.slugToNetworkNeighborhood.Get(s)
	}
	return nil
}

// ------------------ watcher.Adaptor methods -----------------------

// ------------------ watcher.WatchResources methods -----------------------

func (nn *NetworkNeighborhoodCacheImpl) WatchResources() []watcher.WatchResource {
	var w []watcher.WatchResource

	// add pod
	p := watcher.NewWatchResource(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	},
		metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + nn.nodeName,
		},
	)
	w = append(w, p)

	// add network neighborhood
	apl := watcher.NewWatchResource(groupVersionResource, metav1.ListOptions{})
	w = append(w, apl)

	return w
}

// ------------------ watcher.Watcher methods -----------------------

func (nn *NetworkNeighborhoodCacheImpl) AddHandler(ctx context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		nn.addPod(obj)
	case "NetworkNeighborhood":
		nn.addNetworkNeighborhood(ctx, obj)
	}
}
func (nn *NetworkNeighborhoodCacheImpl) ModifyHandler(ctx context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		nn.addPod(obj)
	case "NetworkNeighborhood":
		nn.addNetworkNeighborhood(ctx, obj)
	}
}
func (nn *NetworkNeighborhoodCacheImpl) DeleteHandler(_ context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		nn.deletePod(obj)
	case "NetworkNeighborhood":
		nn.deleteNetworkNeighborhood(obj)
	}
}

// ------------------ watch pod methods -----------------------

func (nn *NetworkNeighborhoodCacheImpl) addPod(podU *unstructured.Unstructured) {

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
		nn.removeContainer(container)
	}

	containers := objectcache.ListContainersIDs(pod)
	for _, container := range containers {

		if !nn.slugToContainers.Has(uniqueSlug) {
			nn.slugToContainers.Set(uniqueSlug, mapset.NewSet[string]())
		}
		nn.slugToContainers.Get(uniqueSlug).Add(container)

		if s := nn.slugToState.Get(uniqueSlug); s.mode != helpersv1.Complete {
			// if NN is not complete, do not cache the pod
			continue
		}

		// add the container to the cache
		if nn.containerToSlug.Has(container) {
			continue
		}
		nn.containerToSlug.Set(container, uniqueSlug)

		// if NN exists but is not cached
		if nn.allNetworkNeighborhoods.Contains(uniqueSlug) && !nn.slugToNetworkNeighborhood.Has(uniqueSlug) {

			// get the NN
			networkNeighborhood, err := nn.getNetworkNeighborhood(podU.GetNamespace(), slug)
			if err != nil {
				logger.L().Error("failed to get network neighborhood", helpers.Error(err))
				continue
			}

			nn.slugToNetworkNeighborhood.Set(uniqueSlug, networkNeighborhood)
		}

	}

}

func (nn *NetworkNeighborhoodCacheImpl) deletePod(obj *unstructured.Unstructured) {

	pod, err := objectcache.UnstructuredToPod(obj)
	if err != nil {
		logger.L().Error("ApplicationProfileCacheImpl: failed to unmarshal pod", helpers.String("namespace", obj.GetNamespace()), helpers.String("pod", obj.GetName()), helpers.Error(err))
		return
	}

	containers := objectcache.ListContainersIDs(pod)
	for _, container := range containers {
		nn.removeContainer(container)
	}
}
func (nn *NetworkNeighborhoodCacheImpl) removeContainer(containerID string) {

	uniqueSlug := nn.containerToSlug.Get(containerID)
	nn.containerToSlug.Delete(containerID)

	// remove pod form the network neighborhood mapping
	if nn.slugToContainers.Has(uniqueSlug) {
		nn.slugToContainers.Get(uniqueSlug).Remove(containerID)
		if nn.slugToContainers.Get(uniqueSlug).Cardinality() == 0 {
			// remove full network neighborhood from cache
			nn.slugToContainers.Delete(uniqueSlug)
			nn.allNetworkNeighborhoods.Remove(uniqueSlug)
			nn.slugToNetworkNeighborhood.Delete(uniqueSlug)
			logger.L().Debug("deleted pod from network neighborhood cache", helpers.String("containerID", containerID), helpers.String("uniqueSlug", uniqueSlug))
		}
	}
}

// ------------------ watch network neighborhood methods -----------------------
func (nn *NetworkNeighborhoodCacheImpl) addNetworkNeighborhood(_ context.Context, obj *unstructured.Unstructured) {
	nnName := objectcache.UnstructuredUniqueName(obj)

	appProfile, err := unstructuredToNetworkNeighborhood(obj)
	if err != nil {
		logger.L().Error("failed to unmarshal network neighborhood", helpers.String("name", nnName), helpers.Error(err))
		return
	}
	apState := newNetworkNeighborhoodState(appProfile)
	nn.slugToState.Set(nnName, apState)

	// the cache holds only completed network neighborhoods.
	// check if the network neighborhood is completed
	// if status was completed and now is not (e.g. mode changed from complete to partial), remove from cache
	if apState.status != helpersv1.Completed {
		if nn.slugToNetworkNeighborhood.Has(nnName) {
			nn.slugToNetworkNeighborhood.Delete(nnName)
			nn.allNetworkNeighborhoods.Remove(nnName)
		}
		return
	}

	// add to the cache
	nn.allNetworkNeighborhoods.Add(nnName)

	if nn.slugToContainers.Has(nnName) {
		// get the full network neighborhood from the storage
		// the watch only returns the metadata
		fullNN, err := nn.getNetworkNeighborhood(appProfile.GetNamespace(), appProfile.GetName())
		if err != nil {
			logger.L().Error("failed to get full network neighborhood", helpers.Error(err))
			return
		}
		nn.slugToNetworkNeighborhood.Set(nnName, fullNN)
		for _, i := range nn.slugToContainers.Get(nnName).ToSlice() {
			nn.containerToSlug.Set(i, nnName)
		}

		logger.L().Debug("added pod to network neighborhood cache", helpers.String("name", nnName))
	}
}

func (nn *NetworkNeighborhoodCacheImpl) deleteNetworkNeighborhood(obj *unstructured.Unstructured) {
	nnName := objectcache.UnstructuredUniqueName(obj)
	nn.slugToNetworkNeighborhood.Delete(nnName)
	nn.slugToState.Delete(nnName)
	nn.allNetworkNeighborhoods.Remove(nnName)

	logger.L().Info("deleted network neighborhood from cache", helpers.String("uniqueSlug", nnName))
}

func (nn *NetworkNeighborhoodCacheImpl) getNetworkNeighborhood(namespace, name string) (*v1beta1.NetworkNeighborhood, error) {

	u, err := nn.k8sClient.GetDynamicClient().Resource(groupVersionResource).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return unstructuredToNetworkNeighborhood(u)
}

func unstructuredToNetworkNeighborhood(obj *unstructured.Unstructured) (*v1beta1.NetworkNeighborhood, error) {

	ap := &v1beta1.NetworkNeighborhood{}
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
	slug, err := instanceID.GetSlug(true)
	if err != nil {
		return "", fmt.Errorf("failed to get slug")
	}
	return slug, nil

}
