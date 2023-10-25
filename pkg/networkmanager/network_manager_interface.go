package networkmanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
)

type NetworkManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	SaveNetworkEvent(containerName, podName string, networkEvent tracernetworktype.Event)
}
