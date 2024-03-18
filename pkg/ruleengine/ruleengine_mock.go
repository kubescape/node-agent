package ruleengine

import (
	corev1 "k8s.io/api/core/v1"
)

var _ K8sObjectProvider = (*K8sObjectProviderMock)(nil)

type K8sObjectProviderMock struct {
	PodSpec            corev1.PodSpec
	ApiServerIpAddress string
}

func (k *K8sObjectProviderMock) GetPodSpec(namespace, podName string) (*corev1.PodSpec, error) {
	return &k.PodSpec, nil
}
func (k *K8sObjectProviderMock) GetApiServerIpAddress() (string, error) {
	return k.ApiServerIpAddress, nil
}
