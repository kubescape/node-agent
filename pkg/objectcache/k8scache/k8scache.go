package k8scache

import (
	"context"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/watcher"
	"time"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/goradd/maps"
	corev1 "k8s.io/api/core/v1"
)

var _ objectcache.K8sObjectCache = (*K8sObjectCacheImpl)(nil)
var _ watcher.Adaptor = (*K8sObjectCacheImpl)(nil)

type K8sObjectCacheImpl struct {
	nodeName  string
	k8sClient k8sclient.K8sClientInterface
	podSpec   maps.SafeMap[string, *corev1.PodSpec]
	podStatus maps.SafeMap[string, *corev1.PodStatus]

	apiServerIpAddress string
}

func NewK8sObjectCache(nodeName string, k8sClient k8sclient.K8sClientInterface) (*K8sObjectCacheImpl, error) {
	k := &K8sObjectCacheImpl{
		k8sClient: k8sClient,
		nodeName:  nodeName,
	}

	if err := k.setApiServerIpAddress(); err != nil {
		return k, err
	}

	return k, nil
}

// GetPodSpec returns the pod spec for the given namespace and pod name, if not found returns nil
func (k *K8sObjectCacheImpl) GetPodSpec(namespace, podName string) *corev1.PodSpec {
	p := podKey(namespace, podName)
	if k.podSpec.Has(p) {
		return k.podSpec.Get(p)
	}

	return nil
}

// GetPodSpec returns the pod spec for the given namespace and pod name, if not found returns nil
func (k *K8sObjectCacheImpl) GetPodStatus(namespace, podName string) *corev1.PodStatus {
	p := podKey(namespace, podName)
	if k.podStatus.Has(p) {
		return k.podStatus.Get(p)
	}

	return nil
}

func (k *K8sObjectCacheImpl) GetApiServerIpAddress() string {
	return k.apiServerIpAddress
}

func (k *K8sObjectCacheImpl) AddHandler(_ context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		pod, err := unstructuredToPod(obj)
		if err != nil {
			return
		}
		k.podSpec.Set(podKey(pod.GetNamespace(), pod.GetName()), &pod.Spec)
		k.podStatus.Set(podKey(pod.GetNamespace(), pod.GetName()), &pod.Status)
	}
}

func (k *K8sObjectCacheImpl) ModifyHandler(_ context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		pod, err := unstructuredToPod(obj)
		if err != nil {
			return
		}
		k.podSpec.Set(podKey(pod.GetNamespace(), pod.GetName()), &pod.Spec)
		k.podStatus.Set(podKey(pod.GetNamespace(), pod.GetName()), &pod.Status)
	}
}
func (k *K8sObjectCacheImpl) DeleteHandler(_ context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		pod, err := unstructuredToPod(obj)
		if err != nil {
			return
		}

		// delete the pod spec and status after 1 minute
		key := podKey(pod.GetNamespace(), pod.GetName())
		time.AfterFunc(time.Minute*1, func() {
			k.podSpec.Delete(key)
			k.podStatus.Delete(key)
		})
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
	apiAddress, err := k.k8sClient.GetKubernetesClient().CoreV1().Services("default").Get(context.Background(), "kubernetes", metav1.GetOptions{})
	if err != nil {
		return err
	}
	// TODO: is this the correct approach?
	k.apiServerIpAddress = apiAddress.Spec.ClusterIP
	return nil
}

func podKey(namespace, podName string) string {
	return namespace + "/" + podName
}
func unstructuredToPod(obj *unstructured.Unstructured) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, pod); err != nil {
		return nil, err
	}
	return pod, nil
}
