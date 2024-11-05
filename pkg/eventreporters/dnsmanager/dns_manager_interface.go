package dnsmanager

import (
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

type DNSManagerClient interface {
	ReportEvent(networkEvent tracerdnstype.Event)
}

type DNSResolver interface {
	ResolveIPAddress(ipAddr string) (string, bool)
}
