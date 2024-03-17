package ruleengine

import (
	corev1 "k8s.io/api/core/v1"
)

var _ K8sCache = (*K8sCacheMock)(nil)

type K8sCacheMock struct {
	PodSpec            corev1.PodSpec
	ApiServerIpAddress string
}

func (k *K8sCacheMock) GetPodSpec(namespace, podName string) (*corev1.PodSpec, error) {
	return &k.PodSpec, nil
}
func (k *K8sCacheMock) GetApiServerIpAddress() (string, error) {
	return k.ApiServerIpAddress, nil
}
