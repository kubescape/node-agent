package relevancymanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type RelevancyManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ContainerReachedMaxTime(containerID string)
	ReportFileExec(containerID, k8sContainerID, file string)
	ReportFileOpen(containerID, k8sContainerID, file string)
}
