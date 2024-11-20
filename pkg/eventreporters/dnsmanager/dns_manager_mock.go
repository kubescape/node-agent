package dnsmanager

import (
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

func (n *DNSManagerMock) ResolveIPAddress(_ string) (string, bool) {
	return "", false
}
