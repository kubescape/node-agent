package hostnetworksensor

import (
	"time"

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/hostnetworksensor"
	"github.com/kubescape/node-agent/pkg/processmanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"istio.io/pkg/cache"
)

const (
	defaultReportTTL   = 10 * time.Minute // Default TTL for reported domains and addresses
	defaultEvictionTTL = 5 * time.Second  // Default TTL for eviction of cache entries
)

type HostNetworkSensor struct {
	reportedDomainsCache   cache.ExpiringCache // Cache for reported domains
	reportedAddressesCache cache.ExpiringCache // Cache for reported addresses
	dnsResolver            dnsmanager.DNSResolver
	processManager         processmanager.ProcessManagerClient
	exporter               exporters.Exporter // Exporter to send the events to
}

var _ hostnetworksensor.HostNetworkSensorClient = (*HostNetworkSensor)(nil)

func CreateHostNetworkSensor(exporter exporters.Exporter, dnsResolver dnsmanager.DNSResolver, processManager processmanager.ProcessManagerClient) (*HostNetworkSensor, error) {
	return &HostNetworkSensor{
		reportedDomainsCache:   cache.NewTTL(defaultReportTTL, defaultEvictionTTL),
		reportedAddressesCache: cache.NewTTL(defaultReportTTL, defaultEvictionTTL),
		dnsResolver:            dnsResolver,
		processManager:         processManager,
		exporter:               exporter,
	}, nil
}

func (hns HostNetworkSensor) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	if event == nil {
		return
	}

	switch eventType {
	case utils.NetworkEventType:
		networkEvent := event.(*tracernetworktype.Event)
		if hns.shouldReportNetworkEvent(networkEvent) {
			hns.reportNetworkEvent(networkEvent)
		}
	case utils.DnsEventType:
		dnsEvent := event.(*tracerdnstype.Event)
		if hns.shouldReportDnsEvent(dnsEvent) {
			hns.reportDnsEvent(dnsEvent)
		}
	}
}
