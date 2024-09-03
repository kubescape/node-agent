package dnsmanager

import (
	"net"

	"github.com/goradd/maps"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

// DNSManager is used to manage DNS events and save IP resolutions. It exposes an API to resolve IP address to domain name.
type DNSManager struct {
	addressToDomainMap maps.SafeMap[string, string] // this map is used to resolve IP address to domain name
	searchedDomains    maps.SafeMap[string, bool]   // this map is used to store the domains that have been searched
}

var _ DNSManagerClient = (*DNSManager)(nil)
var _ DNSResolver = (*DNSManager)(nil)

func CreateDNSManager() *DNSManager {
	return &DNSManager{}
}

func (dm *DNSManager) ReportDNSEvent(dnsEvent tracerdnstype.Event) {

	if len(dnsEvent.Addresses) > 0 {
		for _, address := range dnsEvent.Addresses {
			dm.addressToDomainMap.Set(address, dnsEvent.DNSName)
		}
	} else {
		if dm.searchedDomains.Has(dnsEvent.DNSName) {
			return
		}

		addresses, err := net.LookupIP(dnsEvent.DNSName)
		if err != nil {
			dm.searchedDomains.Set(dnsEvent.DNSName, true)
			return
		}
		for _, address := range addresses {
			dm.addressToDomainMap.Set(address.String(), dnsEvent.DNSName)
		}

		dm.searchedDomains.Set(dnsEvent.DNSName, true)
	}
}

func (dm *DNSManager) ResolveIPAddress(ipAddr string) (string, bool) {
	domain := dm.addressToDomainMap.Get(ipAddr)
	return domain, domain != ""
}
