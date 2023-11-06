package dnsmanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

type DNSManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	SaveNetworkEvent(podName string, networkEvent tracerdnstype.Event)
}
