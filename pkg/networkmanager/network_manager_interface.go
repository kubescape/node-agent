package networkmanager

import containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"

type NetworkManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	SaveNetworkEvent(containerName, podName string, networkEvent *NetworkEvent)
}
