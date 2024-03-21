package k8scache

import (
	"context"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/ruleengine/objectcache"
	"node-agent/pkg/watcher"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/goradd/maps"
	corev1 "k8s.io/api/core/v1"
)

var _ objectcache.K8sObjectCache = (*K8sObjectCacheImpl)(nil)
var _ watcher.Watcher = (*K8sObjectCacheImpl)(nil)

type K8sObjectCacheImpl struct {
	k8sClient          k8sclient.K8sClientInterface
	podSpec            maps.SafeMap[string, *corev1.PodSpec]
	apiServerIpAddress string
}

func NewK8sObjectCache(k8sClient k8sclient.K8sClientInterface) (*K8sObjectCacheImpl, error) {
	k := &K8sObjectCacheImpl{
		k8sClient: k8sClient,
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

func (k *K8sObjectCacheImpl) RuntimeObjAddHandler(obj runtime.Object) {
	switch reflect.TypeOf(obj) {
	case reflect.TypeOf(&corev1.Pod{}):
		pod := obj.(*corev1.Pod)
		k.podSpec.Set(podSpecKey(pod.GetNamespace(), pod.GetName()), &pod.Spec)
	}

}
func (k *K8sObjectCacheImpl) RuntimeObjUpdateHandler(obj runtime.Object) {
	switch reflect.TypeOf(obj) {
	case reflect.TypeOf(&corev1.Pod{}):
		pod := obj.(*corev1.Pod)
		k.podSpec.Set(podSpecKey(pod.GetNamespace(), pod.GetName()), &pod.Spec)
	}
}
func (k *K8sObjectCacheImpl) RuntimeObjDeleteHandler(obj runtime.Object) {
	switch reflect.TypeOf(obj) {
	case reflect.TypeOf(&corev1.Pod{}):
		pod := obj.(*corev1.Pod)
		k.podSpec.Delete(podSpecKey(pod.GetNamespace(), pod.GetName()))
	}
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
