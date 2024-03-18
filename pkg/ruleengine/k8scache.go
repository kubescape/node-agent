package ruleengine

import (
	"fmt"

	"github.com/goradd/maps"
	corev1 "k8s.io/api/core/v1"
)

var _ K8sCache = (*InMemoryK8sCache)(nil)

type InMemoryK8sCache struct {
	podSpec            maps.SafeMap[string, *corev1.PodSpec]
	apiServerIpAddress string
}

// GetPodSpec returns the pod spec for the given namespace and pod name, if not found returns nil
func (k *InMemoryK8sCache) GetPodSpec(namespace, podName string) (*corev1.PodSpec, error) {
	p := podSpecKey(namespace, podName)
	if k.podSpec.Has(p) {
		return k.podSpec.Get(p), nil
	}
	return nil, fmt.Errorf("pod spec not found for %s", p)
}
func (k *InMemoryK8sCache) GetApiServerIpAddress() (string, error) {
	if k.apiServerIpAddress != "" {
		return k.apiServerIpAddress, nil
	}
	return "", fmt.Errorf("api server ip address not found")
}

// GetPodSpec returns the pod spec for the given namespace and pod name, if not found returns nil
func (k *InMemoryK8sCache) SetPodSpec(pod *corev1.Pod) {
	p := podSpecKey(pod.GetNamespace(), pod.GetName())
	k.podSpec.Set(p, &pod.Spec)
}

func (k *InMemoryK8sCache) SetApiServerIpAddress(apiAddress string) {
	k.apiServerIpAddress = apiAddress
}

func podSpecKey(namespace, podName string) string {
	return namespace + "/" + podName
}
