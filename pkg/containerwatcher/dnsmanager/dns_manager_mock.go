package dnsmanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

type DNSManagerMock struct {
}

var _ DNSManagerClient = (*DNSManagerMock)(nil)

func CreateDNSManagerMock() *DNSManagerMock {
	return &DNSManagerMock{}
}

func (am *DNSManagerMock) ContainerCallback(notif containercollection.PubSubEvent) {

}

func (am *DNSManagerMock) SaveNetworkEvent(podName string, event tracerdnstype.Event) {
}
