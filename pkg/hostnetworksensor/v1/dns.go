package hostnetworksensor

import (
	"strings"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

func (hns *HostNetworkSensor) reportDnsEvent(dnsEvent *tracerdnstype.Event) {
	if _, ok := hns.reportedDomainsCache.Get(dnsEvent.DNSName); ok {
		return
	}

	hns.reportedDomainsCache.Set(dnsEvent.DNSName, nil)

	for _, address := range dnsEvent.Addresses {
		hns.reportedAddressesCache.Set(address, nil)
	}

	result := NetworkScanResult{
		ScanResult: apitypes.NetworkScanAlert{
			Domain:    dnsEvent.DNSName,
			Addresses: dnsEvent.Addresses,
		},
		Event:     dnsEvent.Event,
		Timestamp: time.Unix(0, int64(dnsEvent.Timestamp)),
		Pid:       int(dnsEvent.Pid),
		ProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				PID: uint32(dnsEvent.Pid),
			},
		},
	}
	hns.setProcessTree(&result)

	hns.exporter.SendNetworkScanAlert(result)
}

// shouldReportDnsEvent determines if a DNS event should be reported.
// We don't want to report DNS events that are in-cluster communication.
func (hns *HostNetworkSensor) shouldReportDnsEvent(dnsEvent *tracerdnstype.Event) bool {
	if dnsEvent.DNSName == "" {
		return false
	}

	if strings.HasSuffix(dnsEvent.DNSName, "in-addr.arpa.") {
		return false
	}

	if strings.HasSuffix(dnsEvent.DNSName, "svc.cluster.local.") {
		return false
	}

	return true
}
