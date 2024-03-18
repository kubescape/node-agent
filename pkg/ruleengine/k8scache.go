package ruleengine

import (
	"context"
	"fmt"
	"node-agent/pkg/k8sclient"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/goradd/maps"
	corev1 "k8s.io/api/core/v1"
)

var _ K8sObjectProvider = (*K8sObjectProviderImpl)(nil)

type K8sObjectProviderImpl struct {
	k8sClient          k8sclient.K8sClientInterface
	podSpec            maps.SafeMap[string, *corev1.PodSpec]
	apiServerIpAddress string
}

func NewK8sObjectProvider(k8sClient k8sclient.K8sClientInterface) *K8sObjectProviderImpl {
	return &K8sObjectProviderImpl{
		k8sClient: k8sClient,
	}
}

// GetPodSpec returns the pod spec for the given namespace and pod name, if not found returns nil
func (k *K8sObjectProviderImpl) GetPodSpec(namespace, podName string) (*corev1.PodSpec, error) {
	p := podSpecKey(namespace, podName)
	if k.podSpec.Has(p) {
		return k.podSpec.Get(p), nil
	}
	// fallback: get pod spec from k8s
	// TODO: remove fallback once the cache is managed by watchers
	if err := k.SetPodSpec(namespace, podName); err != nil {
		return nil, err
	}
	if k.podSpec.Has(p) {
		return k.podSpec.Get(p), nil
	}

	return nil, fmt.Errorf("pod spec not found for %s", p)
}
func (k *K8sObjectProviderImpl) GetApiServerIpAddress() (string, error) {
	if k.apiServerIpAddress != "" {
		return k.apiServerIpAddress, nil
	}

	// fallback: get service from k8s
	// TODO: remove fallback once the cache is managed by watchers
	if err := k.SetApiServerIpAddress(); err != nil {
		return "", err
	}
	if k.apiServerIpAddress != "" {
		return k.apiServerIpAddress, nil
	}

	return "", fmt.Errorf("api server ip address not found")
}

func (k *K8sObjectProviderImpl) SetPodSpec(namespace, podName string) error {
	// get pod
	pod, err := k.k8sClient.GetKubernetesClient().CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	p := podSpecKey(namespace, podName)
	k.podSpec.Set(p, &pod.Spec)
	return nil
}

func (k *K8sObjectProviderImpl) SetApiServerIpAddress() error {
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
