package dnsmanager

import (
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	lru "github.com/hashicorp/golang-lru/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
	"istio.io/pkg/cache"
)

// DNSManager is used to manage DNS events and save IP resolutions.
type DNSManager struct {
	addressToDomainMap       *lru.Cache[string, string]
	lookupCache              cache.ExpiringCache                                             // Cache for DNS lookups
	failureCache             cache.ExpiringCache                                             // Cache for failed lookups
	containerToCloudServices maps.SafeMap[string, *maps.SafeMap[uint32, mapset.Set[string]]] // key: containerId, value: map of pid to cloud services
}

type cacheEntry struct {
	addresses []string
}

const (
	defaultPositiveTTL  = 1 * time.Minute // Default TTL for successful lookups
	defaultNegativeTTL  = 5 * time.Second // Default TTL for failed lookups
	maxServiceCacheSize = 50              // Maximum number of cloud services to cache per container
)

var _ DNSManagerClient = (*DNSManager)(nil)
var _ DNSResolver = (*DNSManager)(nil)

func CreateDNSManager(size int) *DNSManager {
	addressToDomainMap, err := lru.New[string, string](size)
	if err != nil {
		logger.L().Fatal("creating lru cache", helpers.Error(err))
		return nil
	}

	return &DNSManager{
		addressToDomainMap: addressToDomainMap,
		lookupCache:        cache.NewTTL(defaultPositiveTTL, defaultPositiveTTL),
		failureCache:       cache.NewTTL(defaultNegativeTTL, defaultNegativeTTL),
	}
}

func (dm *DNSManager) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		dm.containerToCloudServices.Set(notif.Container.Runtime.ContainerID, maps.NewSafeMap[uint32, mapset.Set[string]]())
	case containercollection.EventTypeRemoveContainer:
		dm.containerToCloudServices.Delete(notif.Container.Runtime.ContainerID)
	}
}

func (dm *DNSManager) ReportEvent(dnsEvent utils.K8sEvent) {
	//if isCloudService(dnsEvent.DNSName) {
	//	if pidToServices, found := dm.containerToCloudServices.Load(dnsEvent.Runtime.ContainerID); found {
	// Guard against cache size getting too large by checking the cardinality per container and pid
	//		if services, found := pidToServices.Load(dnsEvent.Pid); found {
	//			if services.Cardinality() < maxServiceCacheSize {
	//				services.Add(dnsEvent.DNSName)
	//			}
	//		} else {
	// Create a new set for this pid
	//			servicesSet := mapset.NewSet[string]()
	//			servicesSet.Add(dnsEvent.DNSName)
	//			pidToServices.Set(dnsEvent.Pid, servicesSet)
	//		}
	//	}
	//}

	//if len(dnsEvent.Addresses) > 0 {
	//	for _, address := range dnsEvent.Addresses {
	//		dm.addressToDomainMap.Add(address, dnsEvent.DNSName)
	//	}

	// Update the cache with these known good addresses
	//	dm.lookupCache.Set(dnsEvent.DNSName, cacheEntry{
	//		addresses: dnsEvent.Addresses,
	//	})
	//	return
	//}

	// Check if we've recently failed to look up this domain
	//if _, found := dm.failureCache.Get(dnsEvent.DNSName); found {
	//	return
	//}

	// Check if we have a cached result
	//if cached, found := dm.lookupCache.Get(dnsEvent.DNSName); found {
	//	entry := cached.(cacheEntry)
	// Use cached addresses
	//	for _, addr := range entry.addresses {
	//		dm.addressToDomainMap.Add(addr, dnsEvent.DNSName)
	//	}
	//	return
	//}

	//// Only perform lookup if we don't have cached results
	//addresses, err := net.LookupIP(dnsEvent.DNSName)
	//if err != nil {
	// Cache the failure - we just need to store something, using empty struct
	//	dm.failureCache.Set(dnsEvent.DNSName, struct{}{})
	//	return
	//}

	// Convert addresses to strings and store them
	//addrStrings := make([]string, 0, len(addresses))
	//for _, addr := range addresses {
	//	addrStr := addr.String()
	//	addrStrings = append(addrStrings, addrStr)
	//	dm.addressToDomainMap.Add(addrStr, dnsEvent.DNSName)
	//}

	// Cache the successful lookup
	//dm.lookupCache.Set(dnsEvent.DNSName, cacheEntry{
	//	addresses: addrStrings,
	//})
}

func (dm *DNSManager) ResolveIPAddress(ipAddr string) (string, bool) {
	domain, found := dm.addressToDomainMap.Get(ipAddr)
	return domain, found
}

func (dm *DNSManager) ResolveContainerProcessToCloudServices(containerId string, pid uint32) mapset.Set[string] {
	if pidToServices, found := dm.containerToCloudServices.Load(containerId); found {
		if services, found := pidToServices.Load(pid); found {
			return services
		}
	}
	return nil
}

func isCloudService(domain string) bool {
	domain = strings.ToLower(domain)
	// Common cloud service domains
	awsDomains := []string{
		"amazonaws.com.",
		"cloudfront.net.",
		"aws.amazon.com.",
		"elasticbeanstalk.com.",
	}

	azureDomains := []string{
		"azure.com.",
		"azurewebsites.net.",
		"cloudapp.net.",
		"azure-api.net.",
	}

	gcpDomains := []string{
		"googleapis.com.",
		"appspot.com.",
		"cloudfunctions.net.",
		"run.app.",
	}

	// Combine all cloud domains
	allCloudDomains := append(awsDomains, azureDomains...)
	allCloudDomains = append(allCloudDomains, gcpDomains...)

	// Check if the input domain ends with any of the cloud domains
	for _, cloudDomain := range allCloudDomains {
		if strings.HasSuffix(domain, cloudDomain) {
			return true
		}
	}

	return false
}
