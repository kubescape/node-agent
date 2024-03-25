package networkneighborscache

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
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var _ objectcache.NetworkNeighborsCache = (*NetworkNeighborsCacheImp)(nil)
var _ watcher.Adaptor = (*NetworkNeighborsCacheImp)(nil)

var _ objectcache.NetworkNeighborsCache = (*NetworkNeighborsCacheImp)(nil)

type NetworkNeighborsCacheImp struct {
	nodeName              string
	k8sClient             k8sclient.K8sClientInterface
	podToSlug             maps.SafeMap[string, string]                    // cache the pod to slug mapping, this will enable a quick lookup of the network neighbors
	slugToNetworkNeighbor maps.SafeMap[string, *v1beta1.NetworkNeighbors] // cache the network neighbors
	slugToPods            maps.SafeMap[string, mapset.Set[string]]        // cache the pods that belong to the network neighbors, this will enable removing from cache AP without pods
	allNeighbors          mapset.Set[string]                              // cache all the network neighbors that are ready. this will enable removing from cache AP without pods that are running on the same node
}

func NewNetworkNeighborsCache(nodeName string, k8sClient k8sclient.K8sClientInterface) *NetworkNeighborsCacheImp {
	return &NetworkNeighborsCacheImp{
		nodeName:     nodeName,
		k8sClient:    k8sClient,
		podToSlug:    maps.SafeMap[string, string]{},
		slugToPods:   maps.SafeMap[string, mapset.Set[string]]{},
		allNeighbors: mapset.NewSet[string](),
	}

}

// ------------------ objectcache.NetworkNeighborsCache methods -----------------------

func (np *NetworkNeighborsCacheImp) GetNetworkNeighbors(namespace, name string) *v1beta1.NetworkNeighbors {
	uniqueName := objectcache.UniqueName(namespace, name)
	if np.slugToNetworkNeighbor.Has(uniqueName) {
		return np.slugToNetworkNeighbor.Get(uniqueName)
	}
	return nil
}

// ------------------ watcher.Adaptor methods -----------------------

// ------------------ watcher.WatchResources methods -----------------------

func (np *NetworkNeighborsCacheImp) WatchResources() []watcher.WatchResource {
	w := []watcher.WatchResource{}

	// add pod
	p := watcher.NewWatchResource(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	},
		metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + np.nodeName,
		},
	)
	w = append(w, p)

	// add network neighbors
	apl := watcher.NewWatchResource(schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1beta1",
		Resource: "networkneighborses",
	}, metav1.ListOptions{})
	w = append(w, apl)

	return w
}

// ------------------ watcher.Watcher methods -----------------------
func (np *NetworkNeighborsCacheImp) AddHandler(ctx context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		np.addPod(obj)
	case "NetworkNeighbors":
		np.addNetworkNeighbor(ctx, obj)
	}
}
func (np *NetworkNeighborsCacheImp) ModifyHandler(ctx context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		// do nothing
	case "NetworkNeighbors":
		np.addNetworkNeighbor(ctx, obj)
	}
}
func (np *NetworkNeighborsCacheImp) DeleteHandler(_ context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		np.deletePod(obj)
	case "NetworkNeighbors":
		np.deleteNetworkNeighbor(obj)
	}
}

// ------------------ watch pod methods -----------------------

func (np *NetworkNeighborsCacheImp) addPod(podU *unstructured.Unstructured) {
	podName := objectcache.UnstructuredUniqueName(podU)

	if np.podToSlug.Has(podName) {
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

	slug, err := np.getNetworkNeighborNameFromPod(pod)
	if err != nil {
		logger.L().Error("failed to get network neighbors name from pod", helpers.Error(err))
		return
	}

	uniqueSlug := objectcache.UniqueName(pod.GetNamespace(), slug)
	np.podToSlug.Set(podName, uniqueSlug)

	if !np.slugToPods.Has(uniqueSlug) {
		np.slugToPods.Set(uniqueSlug, mapset.NewSet[string]())
	}
	np.slugToPods.Get(uniqueSlug).Add(podName)

	// if network neighbors exists but is not cached
	if np.allNeighbors.Contains(uniqueSlug) && !np.slugToNetworkNeighbor.Has(uniqueSlug) {

		// get the network neighbors
		netNeighbor, err := np.getNetworkNeighbors(pod.GetNamespace(), slug)
		if err != nil {
			logger.L().Error("failed to get network neighbors", helpers.Error(err))
			return
		}
		np.slugToNetworkNeighbor.Set(uniqueSlug, netNeighbor)
	}
}

func (np *NetworkNeighborsCacheImp) deletePod(obj *unstructured.Unstructured) {
	podName := objectcache.UnstructuredUniqueName(obj)
	uniqueSlug := np.podToSlug.Get(podName)
	np.podToSlug.Delete(podName)

	// remove pod form the network neighbors mapping
	if np.slugToPods.Has(uniqueSlug) {
		np.slugToPods.Get(uniqueSlug).Remove(podName)
		if np.slugToPods.Get(uniqueSlug).Cardinality() == 0 {
			np.slugToPods.Delete(uniqueSlug)
			// remove full network neighbors from cache
			np.slugToNetworkNeighbor.Delete(uniqueSlug)
		}
	}
}

// ------------------ watch network neighbors methods -----------------------
func (np *NetworkNeighborsCacheImp) addNetworkNeighbor(_ context.Context, obj *unstructured.Unstructured) {
	nnName := objectcache.UnstructuredUniqueName(obj)

	netNeighbor, err := unstructuredToNetworkNeighbors(obj)
	if err != nil {
		logger.L().Error("failed to unmarshal network neighbors", helpers.String("name", nnName), helpers.Error(err))
		return
	}

	// check if the network neighbors is ready
	// TODO: @amir
	// if was ready and now is not, remove from cache
	// if np.slugToNetworkNeighbor.Has(nnName) {
	// 	return
	// }

	// get the full network neighbors from the storage
	// the watch only returns the metadata
	fullAP, err := np.getNetworkNeighbors(netNeighbor.GetNamespace(), netNeighbor.GetName())
	if err != nil {
		logger.L().Error("failed to get full network neighbors", helpers.Error(err))
		return
	}

	np.slugToNetworkNeighbor.Set(nnName, fullAP)
	np.allNeighbors.Add(nnName)
	np.podToSlug.Range(func(podName, uniqueSlug string) bool {
		if uniqueSlug == nnName {
			if !np.slugToPods.Has(uniqueSlug) {
				np.slugToPods.Set(uniqueSlug, mapset.NewSet[string]())
			}
			np.slugToPods.Get(uniqueSlug).Add(podName)
		}
		return true
	})
}

func (np *NetworkNeighborsCacheImp) deleteNetworkNeighbor(obj *unstructured.Unstructured) {
	nnName := objectcache.UnstructuredUniqueName(obj)
	np.slugToNetworkNeighbor.Delete(nnName)
	np.allNeighbors.Remove(nnName)
	np.slugToPods.Delete(nnName)
}

func unstructuredToNetworkNeighbors(obj *unstructured.Unstructured) (*v1beta1.NetworkNeighbors, error) {
	bytes, err := obj.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var np *v1beta1.NetworkNeighbors
	err = json.Unmarshal(bytes, &np)
	if err != nil {
		return nil, err
	}
	return np, nil
}
func (np *NetworkNeighborsCacheImp) getNetworkNeighbors(namespace, name string) (*v1beta1.NetworkNeighbors, error) {
	gvr := schema.GroupVersionResource{
		Group:    "spdx.softwarecomposition.kubescape.io",
		Version:  "v1beta1",
		Resource: "networkneighborses",
	}
	u, err := np.k8sClient.GetDynamicClient().Resource(gvr).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return unstructuredToNetworkNeighbors(u)
}

func (np *NetworkNeighborsCacheImp) getNetworkNeighborNameFromPod(pod workloadinterface.IWorkload) (string, error) {
	// find parentWlid
	kind, name, err := np.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return "", err
	}

	return kind + "/" + name, nil
}
