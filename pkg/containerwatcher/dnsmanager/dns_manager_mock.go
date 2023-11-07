package dnsmanager

import (
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

func (n *DNSManagerMock) ContainerCallback(notif containercollection.PubSubEvent) {

}

func (n *DNSManagerMock) SaveNetworkEvent(podName string, event tracerdnstype.Event) {
}

func (n *DNSManagerMock) ResolveIPAddress(ipAddr string) (string, bool) {
	return "", false
}
