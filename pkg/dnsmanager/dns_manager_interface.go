package dnsmanager

import (
	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

type DNSManagerClient interface {
	ReportEvent(networkEvent tracerdnstype.Event)
	ContainerCallback(notif containercollection.PubSubEvent)
}

type DNSResolver interface {
	ResolveIPAddress(ipAddr string) (string, bool)
	ResolveContainerProcessToCloudServices(containerId string, pid uint32) mapset.Set[string]
}
