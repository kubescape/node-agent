package dnsmanager

import (
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

type DNSManagerClient interface {
	// ContainerCallback(notif containercollection.PubSubEvent)
	SaveNetworkEvent(podName string, networkEvent tracerdnstype.Event)
}

type DNSResolver interface {
	ResolveIPAddress(ipAddr string) (string, bool)
}
