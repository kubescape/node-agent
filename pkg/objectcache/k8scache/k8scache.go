package k8scache

import (
	"context"
	"fmt"
	"os"

	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/watcher"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	corev1 "k8s.io/api/core/v1"
)

var _ objectcache.K8sObjectCache = (*K8sObjectCacheImpl)(nil)
var _ watcher.Adaptor = (*K8sObjectCacheImpl)(nil)

type K8sObjectCacheImpl struct {
	nodeName                string
	k8sClient               k8sclient.K8sClientInterface
	pods                    maps.SafeMap[string, *corev1.Pod]
	apiServerIpAddress      string
	preRunningContainersIDs mapset.Set[string]
	containerIDToSharedData maps.SafeMap[string, *utils.WatchedContainerData]
}

func NewK8sObjectCache(nodeName string, k8sClient k8sclient.K8sClientInterface, preRunningContainersIDs mapset.Set[string]) (*K8sObjectCacheImpl, error) {
	k := &K8sObjectCacheImpl{
		k8sClient:               k8sClient,
		nodeName:                nodeName,
		pods:                    maps.SafeMap[string, *corev1.Pod]{},
		preRunningContainersIDs: preRunningContainersIDs,
		containerIDToSharedData: maps.SafeMap[string, *utils.WatchedContainerData]{},
	}

	if err := k.setApiServerIpAddress(); err != nil {
		return k, err
	}

	return k, nil
}

// IsPreRunningContainer returns true if the container was running before the agent started
func (k *K8sObjectCacheImpl) IsPreRunningContainer(containerID string) bool {
	return k.preRunningContainersIDs.Contains(containerID)
}

// GetPodSpec returns the pod spec for the given namespace and pod name, if not found returns nil
func (k *K8sObjectCacheImpl) GetPodSpec(namespace, podName string) *corev1.PodSpec {
	p := podKey(namespace, podName)
	if pod, ok := k.pods.Load(p); ok {
		return &pod.Spec
	}

	return nil
}

// GetPodStatus returns the pod status for the given namespace and pod name, if not found returns nil
func (k *K8sObjectCacheImpl) GetPodStatus(namespace, podName string) *corev1.PodStatus {
	p := podKey(namespace, podName)
	if k.pods.Has(p) {
		status := k.pods.Get(p).Status
		return &status
	}

	return nil
}

// GetPod returns the pod for the given namespace and pod name, if not found returns nil
func (k *K8sObjectCacheImpl) GetPod(namespace, podName string) *corev1.Pod {
	p := podKey(namespace, podName)
	if pod, ok := k.pods.Load(p); ok {
		return pod
	}

	return nil
}

func (k *K8sObjectCacheImpl) GetApiServerIpAddress() string {
	return k.apiServerIpAddress
}

func (k *K8sObjectCacheImpl) GetPods() []*corev1.Pod {
	return k.pods.Values()
}

func (k *K8sObjectCacheImpl) SetSharedContainerData(containerID string, data *utils.WatchedContainerData) {
	k.containerIDToSharedData.Set(containerID, data)
}

func (k *K8sObjectCacheImpl) GetSharedContainerData(containerID string) *utils.WatchedContainerData {
	if data, ok := k.containerIDToSharedData.Load(containerID); ok {
		return data
	}

	return nil
}

func (k *K8sObjectCacheImpl) DeleteSharedContainerData(containerID string) {
	k.containerIDToSharedData.Delete(containerID)
}

func (k *K8sObjectCacheImpl) AddHandler(_ context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		k.pods.Set(podKey(pod.GetNamespace(), pod.GetName()), pod)
	}
}

func (k *K8sObjectCacheImpl) ModifyHandler(_ context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		k.pods.Set(podKey(pod.GetNamespace(), pod.GetName()), pod)
	}
}

func (k *K8sObjectCacheImpl) DeleteHandler(_ context.Context, obj runtime.Object) {
	if pod, ok := obj.(*corev1.Pod); ok {
		k.pods.Delete(podKey(pod.GetNamespace(), pod.GetName()))
	}
}

func (k *K8sObjectCacheImpl) WatchResources() []watcher.WatchResource {
	// add pod
	p := watcher.NewWatchResource(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	},
		metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + k.nodeName,
		},
	)

	return []watcher.WatchResource{p}
}

func (k *K8sObjectCacheImpl) setApiServerIpAddress() error {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		return fmt.Errorf("KUBERNETES_SERVICE_HOST environment variable not set")
	}
	k.apiServerIpAddress = host
	return nil
}

func podKey(namespace, podName string) string {
	return namespace + "/" + podName
}
