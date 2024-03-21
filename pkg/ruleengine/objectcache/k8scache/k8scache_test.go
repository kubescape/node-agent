package k8scache

import "node-agent/pkg/k8sclient"

func NewK8sObjectCacheMock(k8sClient k8sclient.K8sClientInterface) *K8sObjectCacheImpl {
	return &K8sObjectCacheImpl{
		k8sClient:          k8sClient,
		apiServerIpAddress: "127.0.0.1",
	}
}
