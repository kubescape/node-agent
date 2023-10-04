package relevancymanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type RelevancyManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ReportFileAccess(k8sContainerID, file string)
}
