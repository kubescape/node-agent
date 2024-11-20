package dnsmanager

import (
	"net"
	"time"

	"github.com/goradd/maps"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"istio.io/pkg/cache"
)

// DNSManager is used to manage DNS events and save IP resolutions.
type DNSManager struct {
	addressToDomainMap maps.SafeMap[string, string]
	lookupCache        cache.ExpiringCache // Cache for DNS lookups
	failureCache       cache.ExpiringCache // Cache for failed lookups
}

type cacheEntry struct {
	addresses []string
}

const (
	defaultPositiveTTL = 1 * time.Minute // Default TTL for successful lookups
	defaultNegativeTTL = 5 * time.Second // Default TTL for failed lookups
)

var _ DNSManagerClient = (*DNSManager)(nil)
var _ DNSResolver = (*DNSManager)(nil)

func CreateDNSManager() *DNSManager {
	return &DNSManager{
		// Create TTL caches with their respective expiration times
		lookupCache:  cache.NewTTL(defaultPositiveTTL, defaultPositiveTTL),
		failureCache: cache.NewTTL(defaultNegativeTTL, defaultNegativeTTL),
	}
}

func (dm *DNSManager) ReportEvent(dnsEvent tracerdnstype.Event) {

	if len(dnsEvent.Addresses) > 0 {
		for _, address := range dnsEvent.Addresses {
			dm.addressToDomainMap.Set(address, dnsEvent.DNSName)
		}

		// Update the cache with these known good addresses
		dm.lookupCache.Set(dnsEvent.DNSName, cacheEntry{
			addresses: dnsEvent.Addresses,
		})
		return
	}

	// Check if we've recently failed to look up this domain
	if _, found := dm.failureCache.Get(dnsEvent.DNSName); found {
		return
	}

	// Check if we have a cached result
	if cached, found := dm.lookupCache.Get(dnsEvent.DNSName); found {
		entry := cached.(cacheEntry)
		// Use cached addresses
		for _, addr := range entry.addresses {
			dm.addressToDomainMap.Set(addr, dnsEvent.DNSName)
		}
		return
	}

	// Only perform lookup if we don't have cached results
	addresses, err := net.LookupIP(dnsEvent.DNSName)
	if err != nil {
		// Cache the failure - we just need to store something, using empty struct
		dm.failureCache.Set(dnsEvent.DNSName, struct{}{})
		return
	}

	// Convert addresses to strings and store them
	addrStrings := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		addrStr := addr.String()
		addrStrings = append(addrStrings, addrStr)
		dm.addressToDomainMap.Set(addrStr, dnsEvent.DNSName)
	}

	// Cache the successful lookup
	dm.lookupCache.Set(dnsEvent.DNSName, cacheEntry{
		addresses: addrStrings,
	})
}

func (dm *DNSManager) ResolveIPAddress(ipAddr string) (string, bool) {
	domain := dm.addressToDomainMap.Get(ipAddr)
	return domain, domain != ""
}
