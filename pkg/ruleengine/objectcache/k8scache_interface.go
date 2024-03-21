package objectcache

import (
	corev1 "k8s.io/api/core/v1"
)

type K8sObjectCache interface {
	GetPodSpec(namespace, podName string) *corev1.PodSpec
	GetApiServerIpAddress() string
}

var _ K8sObjectCache = (*K8sObjectCacheMock)(nil)

type K8sObjectCacheMock struct {
	PodSpec            corev1.PodSpec
	ApiServerIpAddress string
}

func (k *K8sObjectCacheMock) GetPodSpec(namespace, podName string) *corev1.PodSpec {
	return &k.PodSpec
}
func (k *K8sObjectCacheMock) GetApiServerIpAddress() string {
	return k.ApiServerIpAddress
}
