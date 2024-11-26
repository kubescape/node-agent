package relevancymanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	v1 "k8s.io/api/core/v1"
)

type RelevancyManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ContainerReachedMaxTime(containerID string)
	ReportFileExec(containerID, k8sContainerID, file string)
	ReportFileOpen(containerID, k8sContainerID, file string)
	HasRelevancyCalculating(pod *v1.Pod) bool
}
