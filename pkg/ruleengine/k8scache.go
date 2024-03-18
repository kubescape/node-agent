package ruleengine

import (
	"fmt"

	"github.com/goradd/maps"
	corev1 "k8s.io/api/core/v1"
)

var _ K8sObjectProvider = (*K8sObjectProviderImpl)(nil)

type K8sObjectProviderImpl struct {
	podSpec            maps.SafeMap[string, *corev1.PodSpec]
	apiServerIpAddress string
}

// GetPodSpec returns the pod spec for the given namespace and pod name, if not found returns nil
func (k *K8sObjectProviderImpl) GetPodSpec(namespace, podName string) (*corev1.PodSpec, error) {
	p := podSpecKey(namespace, podName)
	if k.podSpec.Has(p) {
		return k.podSpec.Get(p), nil
	}
	return nil, fmt.Errorf("pod spec not found for %s", p)
}
func (k *K8sObjectProviderImpl) GetApiServerIpAddress() (string, error) {
	if k.apiServerIpAddress != "" {
		return k.apiServerIpAddress, nil
	}
	return "", fmt.Errorf("api server ip address not found")
}

// GetPodSpec returns the pod spec for the given namespace and pod name, if not found returns nil
func (k *K8sObjectProviderImpl) SetPodSpec(pod *corev1.Pod) {
	p := podSpecKey(pod.GetNamespace(), pod.GetName())
	k.podSpec.Set(p, &pod.Spec)
}

func (k *K8sObjectProviderImpl) SetApiServerIpAddress(apiAddress string) {
	k.apiServerIpAddress = apiAddress
}

func podSpecKey(namespace, podName string) string {
	return namespace + "/" + podName
}
