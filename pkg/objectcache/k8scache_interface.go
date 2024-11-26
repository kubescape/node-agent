package objectcache

import (
	corev1 "k8s.io/api/core/v1"
)

type K8sObjectCache interface {
	GetPodSpec(namespace, podName string) *corev1.PodSpec
	GetPodStatus(namespace, podName string) *corev1.PodStatus
	GetApiServerIpAddress() string
	GetPods() []*corev1.Pod
}

var _ K8sObjectCache = (*K8sObjectCacheMock)(nil)

type K8sObjectCacheMock struct {
	ApiServerIpAddress string
	PodSpec            corev1.PodSpec
	PodStatus          corev1.PodStatus
}

func (k *K8sObjectCacheMock) GetPodSpec(_, _ string) *corev1.PodSpec {
	return &k.PodSpec
}
func (k *K8sObjectCacheMock) GetPodStatus(_, _ string) *corev1.PodStatus {
	return &k.PodStatus
}
func (k *K8sObjectCacheMock) GetApiServerIpAddress() string {
	return k.ApiServerIpAddress
}
func (k *K8sObjectCacheMock) GetPods() []*corev1.Pod {
	return []*corev1.Pod{{Spec: k.PodSpec, Status: k.PodStatus}}
}
