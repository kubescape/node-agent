package objectcache

import (
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/utils"
	corev1 "k8s.io/api/core/v1"
)

type K8sObjectCache interface {
	GetPodSpec(namespace, podName string) *corev1.PodSpec
	GetPodStatus(namespace, podName string) *corev1.PodStatus
	GetApiServerIpAddress() string
	GetPods() []*corev1.Pod
	GetPod(namespace, podName string) *corev1.Pod
	SetSharedContainerData(containerID string, data *utils.WatchedContainerData)
	GetSharedContainerData(containerID string) *utils.WatchedContainerData
	DeleteSharedContainerData(containerID string)
}

var _ K8sObjectCache = (*K8sObjectCacheMock)(nil)

type K8sObjectCacheMock struct {
	ApiServerIpAddress      string
	PodSpec                 corev1.PodSpec
	PodStatus               corev1.PodStatus
	containerIDToSharedData maps.SafeMap[string, *utils.WatchedContainerData]
}

func (k *K8sObjectCacheMock) GetPodSpec(_, _ string) *corev1.PodSpec {
	return &k.PodSpec
}
func (k *K8sObjectCacheMock) GetPodStatus(_, _ string) *corev1.PodStatus {
	return &k.PodStatus
}
func (k *K8sObjectCacheMock) GetPod(_, _ string) *corev1.Pod {
	return &corev1.Pod{Spec: k.PodSpec, Status: k.PodStatus}
}
func (k *K8sObjectCacheMock) GetApiServerIpAddress() string {
	return k.ApiServerIpAddress
}
func (k *K8sObjectCacheMock) GetPods() []*corev1.Pod {
	return []*corev1.Pod{{Spec: k.PodSpec, Status: k.PodStatus}}
}
func (k *K8sObjectCacheMock) SetSharedContainerData(containerID string, data *utils.WatchedContainerData) {
	k.containerIDToSharedData.Set(containerID, data)
}
func (k *K8sObjectCacheMock) GetSharedContainerData(containerID string) *utils.WatchedContainerData {
	if data, ok := k.containerIDToSharedData.Load(containerID); ok {
		return data
	}

	return nil
}
func (k *K8sObjectCacheMock) DeleteSharedContainerData(containerID string) {
	k.containerIDToSharedData.Delete(containerID)
}
