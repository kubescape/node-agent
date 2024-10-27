package networkneighborhoodcache

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
	containerToSlug                maps.SafeMap[string, string]                       // cache the containerID to slug mapping, this will enable a quick lookup of the network neighborhood
	slugToNetworkNeighborhood      maps.SafeMap[string, *v1beta1.NetworkNeighborhood] // cache the network neighborhood
	slugToContainers               maps.SafeMap[string, mapset.Set[string]]           // cache the containerIDs that belong to the network neighborhood, this will enable removing from cache NN without pods
	slugToState                    maps.SafeMap[string, networkNeighborhoodState]     // cache the containerID to slug mapping, this will enable a quick lookup of the network neighborhood
	storageClient                  versioned.SpdxV1beta1Interface
	allNetworkNeighborhoods        mapset.Set[string] // cache all the NN that are ready. this will enable removing from cache NN without pods that are running on the same node
	nodeName                       string
	maxDelaySeconds                int // maximum delay in seconds before getting the full object from the storage
	userManagedNetworkNeighborhood maps.SafeMap[string, *v1beta1.NetworkNeighborhood]
}

func NewNetworkNeighborhoodCache(nodeName string, storageClient versioned.SpdxV1beta1Interface, maxDelaySeconds int) *NetworkNeighborhoodCacheImpl {
	return &NetworkNeighborhoodCacheImpl{
		nodeName:                       nodeName,
		maxDelaySeconds:                maxDelaySeconds,
		storageClient:                  storageClient,
		containerToSlug:                maps.SafeMap[string, string]{},
		slugToContainers:               maps.SafeMap[string, mapset.Set[string]]{},
		allNetworkNeighborhoods:        mapset.NewSet[string](),
		userManagedNetworkNeighborhood: maps.SafeMap[string, *v1beta1.NetworkNeighborhood]{},
	}

}

// ------------------ objectcache.NetworkNeighborhoodCache methods -----------------------

func (nn *NetworkNeighborhoodCacheImpl) GetNetworkNeighborhood(containerID string) *v1beta1.NetworkNeighborhood {
	if s := nn.containerToSlug.Get(containerID); s != "" {
		return nn.slugToNetworkNeighborhood.Get(s)
	}
	return nil
}

func (nn *NetworkNeighborhoodCacheImpl) handleUserManagedNN(netNeighborhood *v1beta1.NetworkNeighborhood) {
	baseNNName := strings.TrimPrefix(netNeighborhood.GetName(), "ug-")
	baseNNUniqueName := objectcache.UniqueName(netNeighborhood.GetNamespace(), baseNNName)

	// Get the full user managed network neighborhood from the storage
	fullNN, err := nn.getNetworkNeighborhood(netNeighborhood.GetNamespace(), netNeighborhood.GetName())
	if err != nil {
		logger.L().Error("failed to get full network neighborhood", helpers.Error(err))
		return
	}

	// Store the user-managed network neighborhood temporarily
	nn.userManagedNetworkNeighborhood.Set(baseNNUniqueName, fullNN)

	// If we have the base network neighborhood cached, fetch a fresh copy and merge.
	// If the base network neighborhood is not cached yet, the merge will be attempted when it's added.
	if nn.slugToNetworkNeighborhood.Has(baseNNUniqueName) {
		// Fetch fresh base network neighborhood from cluster
		freshBaseNN, err := nn.getNetworkNeighborhood(netNeighborhood.GetNamespace(), baseNNName)
		if err != nil {
			logger.L().Error("failed to get fresh base network neighborhood for merging",
				helpers.String("name", baseNNName),
				helpers.String("namespace", netNeighborhood.GetNamespace()),
				helpers.Error(err))
			return
		}

		mergedNN := nn.performMerge(freshBaseNN, fullNN)
		nn.slugToNetworkNeighborhood.Set(baseNNUniqueName, mergedNN)

		// Clean up the user-managed network neighborhood after successful merge
		nn.userManagedNetworkNeighborhood.Delete(baseNNUniqueName)

		logger.L().Debug("merged user-managed network neighborhood with fresh base network neighborhood",
			helpers.String("name", baseNNName),
			helpers.String("namespace", netNeighborhood.GetNamespace()))
	}
}

func (nn *NetworkNeighborhoodCacheImpl) performMerge(normalNN, userManagedNN *v1beta1.NetworkNeighborhood) *v1beta1.NetworkNeighborhood {
	mergedNN := normalNN.DeepCopy()

	// Merge spec containers
	mergedNN.Spec.Containers = nn.mergeContainers(mergedNN.Spec.Containers, userManagedNN.Spec.Containers)
	mergedNN.Spec.InitContainers = nn.mergeContainers(mergedNN.Spec.InitContainers, userManagedNN.Spec.InitContainers)
	mergedNN.Spec.EphemeralContainers = nn.mergeContainers(mergedNN.Spec.EphemeralContainers, userManagedNN.Spec.EphemeralContainers)

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

	// Remove the user-managed annotation
	delete(mergedNN.Annotations, "kubescape.io/managed-by")

	return mergedNN
}

func (nn *NetworkNeighborhoodCacheImpl) mergeContainers(normalContainers, userManagedContainers []v1beta1.NetworkNeighborhoodContainer) []v1beta1.NetworkNeighborhoodContainer {
	// Create a map to store containers by name
	containerMap := make(map[string]int) // map name to index in slice

	// Store indices of normal containers
	for i := range normalContainers {
		containerMap[normalContainers[i].Name] = i
	}

	// Merge or append user containers
	for _, userContainer := range userManagedContainers {
		if idx, exists := containerMap[userContainer.Name]; exists {
			// Directly modify the container in the slice
			nn.mergeContainer(&normalContainers[idx], &userContainer)
		} else {
			normalContainers = append(normalContainers, userContainer)
		}
	}

	return normalContainers
}

func (nn *NetworkNeighborhoodCacheImpl) mergeContainer(normalContainer, userContainer *v1beta1.NetworkNeighborhoodContainer) {
	// Merge ingress rules
	normalContainer.Ingress = nn.mergeNetworkNeighbors(normalContainer.Ingress, userContainer.Ingress)

	// Merge egress rules
	normalContainer.Egress = nn.mergeNetworkNeighbors(normalContainer.Egress, userContainer.Egress)
}

func (nn *NetworkNeighborhoodCacheImpl) mergeNetworkNeighbors(normalNeighbors, userNeighbors []v1beta1.NetworkNeighbor) []v1beta1.NetworkNeighbor {
	// Use map to track existing neighbors by identifier
	neighborMap := make(map[string]int)
	for i, neighbor := range normalNeighbors {
		neighborMap[neighbor.Identifier] = i
	}

	// Merge or append user neighbors
	for _, userNeighbor := range userNeighbors {
		if idx, exists := neighborMap[userNeighbor.Identifier]; exists {
			// Merge existing neighbor
			normalNeighbors[idx] = nn.mergeNetworkNeighbor(normalNeighbors[idx], userNeighbor)
		} else {
			// Append new neighbor
			normalNeighbors = append(normalNeighbors, userNeighbor)
		}
	}

	return normalNeighbors
}

func (nn *NetworkNeighborhoodCacheImpl) mergeNetworkNeighbor(normal, user v1beta1.NetworkNeighbor) v1beta1.NetworkNeighbor {
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
	merged.Ports = nn.mergeNetworkPorts(merged.Ports, user.Ports)

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

func (nn *NetworkNeighborhoodCacheImpl) mergeNetworkPorts(normalPorts, userPorts []v1beta1.NetworkPort) []v1beta1.NetworkPort {
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

func (nn *NetworkNeighborhoodCacheImpl) AddHandler(ctx context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		nn.addPod(pod)
	} else if netNeighborhood, ok := obj.(*v1beta1.NetworkNeighborhood); ok {
		nn.addNetworkNeighborhood(ctx, netNeighborhood)
	}
}

func (nn *NetworkNeighborhoodCacheImpl) ModifyHandler(ctx context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		nn.addPod(pod)
	} else if netNeighborhood, ok := obj.(*v1beta1.NetworkNeighborhood); ok {
		nn.addNetworkNeighborhood(ctx, netNeighborhood)
	}
}

func (nn *NetworkNeighborhoodCacheImpl) DeleteHandler(_ context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		nn.deletePod(pod)
	} else if netNeighborhood, ok := obj.(*v1beta1.NetworkNeighborhood); ok {
		nn.deleteNetworkNeighborhood(netNeighborhood)
	}
}

// ------------------ watch pod methods -----------------------

func (nn *NetworkNeighborhoodCacheImpl) addPod(obj runtime.Object) {
	pod := obj.(*corev1.Pod)

	slug, err := getSlug(pod)
	if err != nil {
		logger.L().Error("NetworkNeighborhoodCacheImpl: failed to get slug", helpers.String("namespace", pod.GetNamespace()), helpers.String("pod", pod.GetName()), helpers.Error(err))
		return
	}

	uniqueSlug := objectcache.UniqueName(pod.GetNamespace(), slug)

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
			networkNeighborhood, err := nn.getNetworkNeighborhood(pod.GetNamespace(), slug)
			if err != nil {
				logger.L().Error("failed to get network neighborhood", helpers.Error(err))
				continue
			}

			nn.slugToNetworkNeighborhood.Set(uniqueSlug, networkNeighborhood)
		}

	}

}

func (nn *NetworkNeighborhoodCacheImpl) deletePod(obj runtime.Object) {
	pod := obj.(*corev1.Pod)

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
func (nn *NetworkNeighborhoodCacheImpl) addNetworkNeighborhood(_ context.Context, obj runtime.Object) {
	netNeighborhood := obj.(*v1beta1.NetworkNeighborhood)
	nnName := objectcache.MetaUniqueName(netNeighborhood)

	isUserManaged := netNeighborhood.Annotations != nil &&
		netNeighborhood.Annotations["kubescape.io/managed-by"] == "User" &&
		strings.HasPrefix(netNeighborhood.GetName(), "ug-")

	if isUserManaged {
		nn.handleUserManagedNN(netNeighborhood)
		return
	}

	nnState := newNetworkNeighborhoodState(netNeighborhood)
	nn.slugToState.Set(nnName, nnState)

	if nnState.status != helpersv1.Completed {
		if nn.slugToNetworkNeighborhood.Has(nnName) {
			nn.slugToNetworkNeighborhood.Delete(nnName)
			nn.allNetworkNeighborhoods.Remove(nnName)
		}
		return
	}

	nn.allNetworkNeighborhoods.Add(nnName)

	if nn.slugToContainers.Has(nnName) {
		time.AfterFunc(utils.RandomDuration(nn.maxDelaySeconds, time.Second), func() {
			nn.addFullNetworkNeighborhood(netNeighborhood, nnName)
		})
	}
}

func (nn *NetworkNeighborhoodCacheImpl) addFullNetworkNeighborhood(netNeighborhood *v1beta1.NetworkNeighborhood, nnName string) {
	fullNN, err := nn.getNetworkNeighborhood(netNeighborhood.GetNamespace(), netNeighborhood.GetName())
	if err != nil {
		logger.L().Error("failed to get full network neighborhood", helpers.Error(err))
		return
	}

	// Check if there's a pending user-managed network neighborhood to merge
	if nn.userManagedNetworkNeighborhood.Has(nnName) {
		userManagedNN := nn.userManagedNetworkNeighborhood.Get(nnName)
		fullNN = nn.performMerge(fullNN, userManagedNN)
		// Clean up the user-managed network neighborhood after successful merge
		nn.userManagedNetworkNeighborhood.Delete(nnName)
		logger.L().Debug("merged pending user-managed network neighborhood", helpers.String("name", nnName))
	}

	nn.slugToNetworkNeighborhood.Set(nnName, fullNN)
	for _, i := range nn.slugToContainers.Get(nnName).ToSlice() {
		nn.containerToSlug.Set(i, nnName)
	}
	logger.L().Debug("added pod to network neighborhood cache", helpers.String("name", nnName))
}

func (nn *NetworkNeighborhoodCacheImpl) deleteNetworkNeighborhood(obj runtime.Object) {
	netNeighborhood := obj.(*v1beta1.NetworkNeighborhood)
	nnName := objectcache.MetaUniqueName(netNeighborhood)

	isUserManaged := netNeighborhood.Annotations != nil &&
		netNeighborhood.Annotations["kubescape.io/managed-by"] == "User" &&
		strings.HasPrefix(netNeighborhood.GetName(), "ug-")

	if isUserManaged {
		// For user-managed network neighborhoods, we need to use the base name for cleanup
		baseNNName := strings.TrimPrefix(netNeighborhood.GetName(), "ug-")
		baseNNUniqueName := objectcache.UniqueName(netNeighborhood.GetNamespace(), baseNNName)
		nn.userManagedNetworkNeighborhood.Delete(baseNNUniqueName)

		logger.L().Debug("deleted user-managed network neighborhood from cache",
			helpers.String("nnName", netNeighborhood.GetName()),
			helpers.String("baseNN", baseNNName))
	} else {
		// For normal network neighborhoods, clean up all related data
		nn.slugToNetworkNeighborhood.Delete(nnName)
		nn.slugToState.Delete(nnName)
		nn.allNetworkNeighborhoods.Remove(nnName)

		logger.L().Debug("deleted network neighborhood from cache",
			helpers.String("uniqueSlug", nnName))
	}

	// Clean up any orphaned user-managed network neighborhoods
	nn.cleanupOrphanedUserManagedNNs()
}

// Add cleanup method for orphaned user-managed network neighborhoods
func (nn *NetworkNeighborhoodCacheImpl) cleanupOrphanedUserManagedNNs() {
	nn.userManagedNetworkNeighborhood.Range(func(key string, value *v1beta1.NetworkNeighborhood) bool {
		if nn.slugToNetworkNeighborhood.Has(key) {
			// If base network neighborhood exists but merge didn't happen for some reason,
			// attempt merge again and cleanup
			if baseNN := nn.slugToNetworkNeighborhood.Get(key); baseNN != nil {
				mergedNN := nn.performMerge(baseNN, value)
				nn.slugToNetworkNeighborhood.Set(key, mergedNN)
				nn.userManagedNetworkNeighborhood.Delete(key)
				logger.L().Debug("cleaned up orphaned user-managed network neighborhood", helpers.String("name", key))
			}
		}
		return true
	})
}

func (nn *NetworkNeighborhoodCacheImpl) getNetworkNeighborhood(namespace, name string) (*v1beta1.NetworkNeighborhood, error) {
	return nn.storageClient.NetworkNeighborhoods(namespace).Get(context.Background(), name, metav1.GetOptions{})
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
