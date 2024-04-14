package v1

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
)

type NetworkManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ReportNetworkEvent(containerID string, event tracernetworktype.Event)
	ReportDroppedEvent(containerID string, event tracernetworktype.Event)
}
