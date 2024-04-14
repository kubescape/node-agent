package networkmanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
)

type NetworkManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ContainerReachedMaxTime(containerID string)
	ReportNetworkEvent(k8sContainerID string, event tracernetworktype.Event)
	ReportDroppedEvent(k8sContainerID string)
}
