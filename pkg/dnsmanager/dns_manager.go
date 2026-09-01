package dnsmanager

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
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
	cacheSize                  int
	perContainerCacheSize      int
	cacheMu                    sync.Mutex
	hostAddressToDomain        *lru.Cache[string, string]
	containerToAddressToDomain *lru.Cache[string, *lru.Cache[string, string]]
	removedContainers          *lru.Cache[string, struct{}]
	lookupCache                cache.ExpiringCache                                             // Cache for DNS lookups
	failureCache               cache.ExpiringCache                                             // Cache for failed lookups
	containerToCloudServices   maps.SafeMap[string, *maps.SafeMap[uint32, mapset.Set[string]]] // key: containerID, value: map of pid to cloud services
}

type cacheEntry struct {
	addresses []string
}

const (
	defaultPositiveTTL           = 1 * time.Minute  // Default TTL for successful lookups
	defaultNegativeTTL           = 5 * time.Second  // Default TTL for failed lookups
	defaultDNSCacheSize          = 10000            // Default total host DNS cache size when non-positive size provided
	maxServiceCacheSize          = 50               // Maximum number of cloud services to cache per container
	defaultPerContainerCacheSize = 1000             // Default maximum number of DNS resolutions cached per container
	minTrackedContainers         = 10               // Minimum number of concurrent containers with DNS caches
	maxRemovedContainersEntries  = 10000            // Maximum number of removed containers to track to prevent resurrection
	defaultRemovalGracePeriod    = 10 * time.Second // Grace period before evicting resolution cache to allow terminal profile save
)

var _ DNSManagerClient = (*DNSManager)(nil)
var _ DNSResolver = (*DNSManager)(nil)

func isHost(containerID string) bool {
	return containerID == armotypes.HostContainerID
}

func CreateDNSManager(size int) *DNSManager {
	if size <= 0 {
		size = defaultDNSCacheSize
	}

	perContainerSize := defaultPerContainerCacheSize
	if size < perContainerSize {
		perContainerSize = size
	}

	maxContainers := size / perContainerSize
	if maxContainers < minTrackedContainers {
		maxContainers = minTrackedContainers
		if maxContainers > size {
			maxContainers = size
		}
		if maxContainers < 1 {
			maxContainers = 1
		}
		perContainerSize = size / maxContainers
		if perContainerSize < 1 {
			perContainerSize = 1
		}
	}

	hostCacheSize := perContainerSize
	if hostCacheSize < 1 {
		hostCacheSize = 1
	}

	hostCache, err := lru.New[string, string](hostCacheSize)
	if err != nil {
		logger.L().Fatal("creating host lru cache", helpers.Error(err))
		return nil
	}

	containerCache, err := lru.New[string, *lru.Cache[string, string]](maxContainers)
	if err != nil {
		logger.L().Fatal("creating container lru cache", helpers.Error(err))
		return nil
	}

	removedCache, err := lru.New[string, struct{}](maxRemovedContainersEntries)
	if err != nil {
		logger.L().Fatal("creating removed containers cache", helpers.Error(err))
		return nil
	}

	return &DNSManager{
		cacheSize:                  size,
		perContainerCacheSize:      perContainerSize,
		hostAddressToDomain:        hostCache,
		containerToAddressToDomain: containerCache,
		removedContainers:          removedCache,
		lookupCache:                cache.NewTTL(defaultPositiveTTL, defaultPositiveTTL),
		failureCache:               cache.NewTTL(defaultNegativeTTL, defaultNegativeTTL),
	}
}

func (dm *DNSManager) isRemoved(containerID string) bool {
	return dm.removedContainers != nil && dm.removedContainers.Contains(containerID)
}

func (dm *DNSManager) getContainerCache(containerID string) *lru.Cache[string, string] {
	if isHost(containerID) {
		return dm.hostAddressToDomain
	}
	if containerID == "" || dm.isRemoved(containerID) {
		return nil
	}
	if cache, found := dm.containerToAddressToDomain.Get(containerID); found {
		return cache
	}

	dm.cacheMu.Lock()
	defer dm.cacheMu.Unlock()

	if dm.isRemoved(containerID) {
		return nil
	}
	if cache, found := dm.containerToAddressToDomain.Get(containerID); found {
		return cache
	}

	cache, err := lru.New[string, string](dm.perContainerCacheSize)
	if err != nil {
		logger.L().Error("creating per-container lru cache", helpers.Error(err), helpers.String("containerID", containerID))
		return nil
	}
	dm.containerToAddressToDomain.Add(containerID, cache)
	return cache
}

func (dm *DNSManager) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		containerID := notif.Container.Runtime.ContainerID
		dm.cacheMu.Lock()
		if dm.removedContainers != nil {
			dm.removedContainers.Remove(containerID)
		}
		if !dm.containerToCloudServices.Has(containerID) {
			dm.containerToCloudServices.Set(containerID, maps.NewSafeMap[uint32, mapset.Set[string]]())
		}
		dm.cacheMu.Unlock()
	case containercollection.EventTypeRemoveContainer:
		containerID := notif.Container.Runtime.ContainerID
		dm.cacheMu.Lock()
		if dm.removedContainers != nil {
			dm.removedContainers.Add(containerID, struct{}{})
		}
		dm.containerToCloudServices.Delete(containerID)
		dm.cacheMu.Unlock()

		time.AfterFunc(defaultRemovalGracePeriod, func() {
			dm.cacheMu.Lock()
			if !dm.containerToCloudServices.Has(containerID) {
				dm.containerToAddressToDomain.Remove(containerID)
			}
			dm.cacheMu.Unlock()
		})
	}
}

func (dm *DNSManager) ReportEvent(dnsEvent utils.DNSEvent) {
	dnsName := dnsEvent.GetDNSName()
	containerID := dnsEvent.GetContainerID()
	if isCloudService(dnsName) {
		if pidToServices, found := dm.containerToCloudServices.Load(containerID); found {
			// Guard against cache size getting too large by checking the cardinality per container and pid
			if services, found := pidToServices.Load(dnsEvent.GetPID()); found {
				if services.Cardinality() < maxServiceCacheSize {
					services.Add(dnsName)
				}
			} else {
				// Create a new set for this pid
				servicesSet := mapset.NewSet[string]()
				servicesSet.Add(dnsName)
				pidToServices.Set(dnsEvent.GetPID(), servicesSet)
			}
		}
	}

	containerCache := dm.getContainerCache(containerID)

	if addresses := dnsEvent.GetAddresses(); len(addresses) > 0 {
		if containerCache != nil {
			for _, address := range addresses {
				if address != "" {
					containerCache.Add(address, dnsName)
				}
			}
		}

		// Update the cache with these known good addresses
		dm.lookupCache.Set(dnsName, cacheEntry{
			addresses: addresses,
		})
		return
	}

	// Check if we've recently failed to look up this domain
	if _, found := dm.failureCache.Get(dnsName); found {
		return
	}

	// Check if we have a cached result
	if cached, found := dm.lookupCache.Get(dnsName); found {
		entry := cached.(cacheEntry)
		// Use cached addresses
		if containerCache != nil {
			for _, addr := range entry.addresses {
				if addr != "" {
					containerCache.Add(addr, dnsName)
				}
			}
		}
		return
	}

	// Only perform lookup if we don't have cached results
	ipAddresses, err := net.LookupIP(dnsName)
	if err != nil {
		// Cache the failure - we just need to store something, using empty struct
		dm.failureCache.Set(dnsName, struct{}{})
		return
	}

	// Convert addresses to strings and store them
	addrStrings := make([]string, 0, len(ipAddresses))
	for _, addr := range ipAddresses {
		addrStr := addr.String()
		if addrStr != "" {
			addrStrings = append(addrStrings, addrStr)
			if containerCache != nil {
				containerCache.Add(addrStr, dnsName)
			}
		}
	}

	// Cache the successful lookup
	dm.lookupCache.Set(dnsName, cacheEntry{
		addresses: addrStrings,
	})
}

func (dm *DNSManager) ResolveIPAddress(containerID string, ipAddr string) (string, bool) {
	if isHost(containerID) {
		if dm.hostAddressToDomain != nil {
			return dm.hostAddressToDomain.Get(ipAddr)
		}
		return "", false
	}
	if containerID == "" {
		return "", false
	}
	if cache, found := dm.containerToAddressToDomain.Get(containerID); found && cache != nil {
		domain, found := cache.Get(ipAddr)
		return domain, found
	}
	return "", false
}

func (dm *DNSManager) ResolveContainerProcessToCloudServices(containerID string, pid uint32) mapset.Set[string] {
	if pidToServices, found := dm.containerToCloudServices.Load(containerID); found {
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
