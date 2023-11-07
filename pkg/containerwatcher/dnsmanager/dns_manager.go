package dnsmanager

import (
	"context"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"

	"github.com/goradd/maps"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

// DNSManager is used to manage DNS events and save IP resolutions. It exposes an API to resolve IP address to domain name.
type DNSManager struct {
	addressToDomainMap maps.SafeMap[string, string] // this map is used to resolve IP address to domain name
}

var _ DNSManagerClient = (*DNSManager)(nil)
var _ DNSResolver = (*DNSManager)(nil)

func CreateDNSManager(ctx context.Context, cfg config.Config, k8sClient k8sclient.K8sClientInterface, storageClient storage.StorageClient, clusterName string) *DNSManager {
	return &DNSManager{}
}

func (dm *DNSManager) ProcessDNSEvent(dnsEvent tracerdnstype.Event) {
	for _, address := range dnsEvent.Addresses {
		dm.addressToDomainMap.Set(address, dnsEvent.DNSName)
	}
}

func (dm *DNSManager) ResolveIPAddress(ipAddr string) (string, bool) {
	domain := dm.addressToDomainMap.Get(ipAddr)
	return domain, domain != ""
}
