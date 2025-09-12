package dnsmanager

import (
	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/utils"
)

type DNSManagerClient interface {
	ReportEvent(networkEvent utils.K8sEvent)
	ContainerCallback(notif containercollection.PubSubEvent)
}

type DNSResolver interface {
	ResolveIPAddress(ipAddr string) (string, bool)
	ResolveContainerProcessToCloudServices(containerId string, pid uint32) mapset.Set[string]
}
