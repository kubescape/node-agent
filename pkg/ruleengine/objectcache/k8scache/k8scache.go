package k8scache

import (
	"context"
	"encoding/json"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/ruleengine/objectcache"
	"node-agent/pkg/watcher"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/goradd/maps"
	corev1 "k8s.io/api/core/v1"
)

var _ objectcache.K8sObjectCache = (*K8sObjectCacheImpl)(nil)
var _ watcher.Adaptor = (*K8sObjectCacheImpl)(nil)

type K8sObjectCacheImpl struct {
	nodeName           string
	k8sClient          k8sclient.K8sClientInterface
	podSpec            maps.SafeMap[string, *corev1.PodSpec]
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
	p := podSpecKey(namespace, podName)
	if k.podSpec.Has(p) {
		return k.podSpec.Get(p)
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
		k.podSpec.Set(podSpecKey(pod.GetNamespace(), pod.GetName()), &pod.Spec)
	}
}

func (k *K8sObjectCacheImpl) ModifyHandler(_ context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		pod, err := unstructuredToPod(obj)
		if err != nil {
			return
		}
		k.podSpec.Set(podSpecKey(pod.GetNamespace(), pod.GetName()), &pod.Spec)
	}
}
func (k *K8sObjectCacheImpl) DeleteHandler(_ context.Context, obj *unstructured.Unstructured) {
	switch obj.GetKind() {
	case "Pod":
		pod, err := unstructuredToPod(obj)
		if err != nil {
			return
		}
		k.podSpec.Delete(podSpecKey(pod.GetNamespace(), pod.GetName()))
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

func podSpecKey(namespace, podName string) string {
	return namespace + "/" + podName
}
func unstructuredToPod(obj *unstructured.Unstructured) (*corev1.Pod, error) {
	bytes, err := obj.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var pod *corev1.Pod
	err = json.Unmarshal(bytes, &pod)
	if err != nil {
		return nil, err
	}
	return pod, nil
}
