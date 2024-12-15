package dnsmanager

import (
	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

type DNSManagerMock struct {
}

var _ DNSManagerClient = (*DNSManagerMock)(nil)
var _ DNSResolver = (*DNSManagerMock)(nil)

func CreateDNSManagerMock() *DNSManagerMock {
	return &DNSManagerMock{}
}

func (n *DNSManagerMock) ReportEvent(_ tracerdnstype.Event) {
}

func (n *DNSManagerMock) ContainerCallback(notif containercollection.PubSubEvent) {
}

func (n *DNSManagerMock) ResolveIPAddress(_ string) (string, bool) {
	return "", false
}

func (n *DNSManagerMock) ResolveContainerProcessToCloudServices(_ string, _ uint32) mapset.Set[string] {
	return nil
}
