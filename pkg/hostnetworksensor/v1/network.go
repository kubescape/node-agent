package hostnetworksensor

import (
	"bytes"
	"net"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
)

func (hns *HostNetworkSensor) reportNetworkEvent(networkEvent *tracernetworktype.Event) {
	if _, ok := hns.reportedAddressesCache.Get(networkEvent.DstEndpoint.Addr); ok {
		return
	}

	hns.reportedAddressesCache.Set(networkEvent.DstEndpoint.Addr, nil)

	domain, ok := hns.dnsResolver.ResolveIPAddress(networkEvent.DstEndpoint.Addr)
	if !ok {
		// Try to resolve the domain name
		domains, err := net.LookupAddr(networkEvent.DstEndpoint.Addr)
		if err != nil {
			domain = ""
		} else {
			if len(domains) > 0 {
				domain = domains[0]
			}
		}
	}

	result := NetworkScanResult{
		ScanResult: apitypes.NetworkScanAlert{
			Domain:    domain,
			Addresses: []string{networkEvent.DstEndpoint.Addr},
		},
		Event:     networkEvent.Event,
		Timestamp: time.Unix(0, int64(networkEvent.Timestamp)),
		Pid:       int(networkEvent.Pid),
		ProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				PID: uint32(networkEvent.Pid),
			},
		},
	}
	hns.setProcessTree(&result)

	hns.exporter.SendNetworkScanAlert(result)
}

func (hns *HostNetworkSensor) shouldReportNetworkEvent(networkEvent *tracernetworktype.Event) bool {
	if networkEvent.PktType != "OUTGOING" {
		return false
	}

	ip := networkEvent.DstEndpoint.Addr

	if ip == "" {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check if IP is localhost
	if parsedIP.IsLoopback() {
		return false
	}

	// Check if IP is in private IP ranges
	privateIPRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		// Class D (Multicast)
		{net.ParseIP("224.0.0.0"), net.ParseIP("239.255.255.255")},
		// Class E (Experimental)
		{net.ParseIP("240.0.0.0"), net.ParseIP("255.255.255.255")},
		// APIPA (sometimes used for local dns)
		{net.ParseIP("169.254.0.0"), net.ParseIP("169.254.255.255")},
	}

	for _, r := range privateIPRanges {
		if bytes.Compare(parsedIP, r.start) >= 0 && bytes.Compare(parsedIP, r.end) <= 0 {
			return false
		}
	}

	return true
}
