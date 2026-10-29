package dnsmanager

import (
	"net"
	"strings"
	"sync"
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
	cacheSize                  int
	perContainerCacheSize      int
	cacheMu                    sync.Mutex
	hostAddressToDomain        *lru.Cache[string, string]
	containerToAddressToDomain *lru.Cache[string, *lru.Cache[string, string]]
	removedContainers          *lru.Cache[string, struct{}]
	lookupCache                cache.ExpiringCache                                                // Cache for DNS lookups
	failureCache               cache.ExpiringCache                                                // Cache for failed lookups
	containerToCloudServices   maps.SafeMap[string, *maps.SafeMap[uint32, *processCloudServices]] // key: containerID, value: map of pid to cloud services
	exitedCloudServices        map[exitedProcess]*processCloudServices                            // cloud services of exited processes, kept for the grace period; guarded by cacheMu
	afterFunc                  func(time.Duration, func()) *time.Timer
}

// processCloudServices holds the cloud services a pid resolved and the
// timestamp of its latest cloud DNS event. Guarded by cacheMu.
type processCloudServices struct {
	names      mapset.Set[string]
	lastSeenNs int64
}

type exitedProcess struct {
	containerID string
	pid         uint32
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
	defaultExitGracePeriod       = 10 * time.Second // Grace period before dropping an exited process's cloud services, so in-flight alerts still get them
)

var _ DNSManagerClient = (*DNSManager)(nil)
var _ DNSResolver = (*DNSManager)(nil)

func CreateDNSManager(size int) *DNSManager {
	if size <= 0 {
		size = defaultDNSCacheSize
	}

	perContainerSize := min(size, defaultPerContainerCacheSize)

	maxContainers := size / perContainerSize
	if maxContainers < minTrackedContainers {
		maxContainers = max(min(minTrackedContainers, size), 1)
		perContainerSize = max(size/maxContainers, 1)
	}

	hostCacheSize := max(perContainerSize, 1)

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
		exitedCloudServices:        make(map[exitedProcess]*processCloudServices),
		afterFunc:                  time.AfterFunc,
	}
}

func (dm *DNSManager) isRemoved(containerID string) bool {
	return dm.removedContainers != nil && dm.removedContainers.Contains(containerID)
}

func (dm *DNSManager) getContainerCache(containerID string) *lru.Cache[string, string] {
	if utils.IsHost(containerID) {
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
			dm.containerToCloudServices.Set(containerID, maps.NewSafeMap[uint32, *processCloudServices]())
		}
		// A container re-added with the same ID must not inherit the retained
		// services of processes that exited before it was removed.
		for key := range dm.exitedCloudServices {
			if key.containerID == containerID {
				delete(dm.exitedCloudServices, key)
			}
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
		dm.cacheMu.Lock()
		if pidToServices, found := dm.containerToCloudServices.Load(containerID); found {
			services, found := pidToServices.Load(dnsEvent.GetPID())
			if !found {
				services = &processCloudServices{names: mapset.NewSet[string]()}
				pidToServices.Set(dnsEvent.GetPID(), services)
			}
			// Guard against cache size getting too large by checking the cardinality per container and pid
			if services.names.Cardinality() < maxServiceCacheSize {
				services.names.Add(dnsName)
			}
			services.lastSeenNs = max(services.lastSeenNs, int64(dnsEvent.GetTimestamp()))
		}
		dm.cacheMu.Unlock()
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

// ReportExitEvent moves the exited process's cloud services out of the live
// map, so a recycled pid starts with an empty set, and keeps them for a grace
// period so alerts raised just before the exit still get them. The exit tracer
// fires for every thread with the thread group id as the pid, so only the group
// leader's exit counts (a procfs exit has no tid and always counts).
func (dm *DNSManager) ReportExitEvent(exitEvent utils.ExitEvent) {
	pid := exitEvent.GetPID()
	if tid := uint32(exitEvent.GetPID64()); tid != 0 && tid != pid {
		return
	}
	containerID := exitEvent.GetContainerID()
	exitNs := int64(exitEvent.GetTimestamp())

	dm.cacheMu.Lock()
	defer dm.cacheMu.Unlock()
	pidToServices, found := dm.containerToCloudServices.Load(containerID)
	if !found {
		return
	}
	services, found := pidToServices.Load(pid)
	// An exit without a timestamp cannot be ordered, and a late exit must not
	// retire services that a process reusing the pid reported after it.
	if !found || exitNs == 0 || services.lastSeenNs > exitNs {
		return
	}
	key := exitedProcess{containerID: containerID, pid: pid}
	dm.exitedCloudServices[key] = services
	pidToServices.Delete(pid)
	dm.afterFunc(defaultExitGracePeriod, func() {
		dm.cacheMu.Lock()
		defer dm.cacheMu.Unlock()
		if dm.exitedCloudServices[key] == services {
			delete(dm.exitedCloudServices, key)
		}
	})
}

func (dm *DNSManager) ResolveIPAddress(containerID string, ipAddr string) (string, bool) {
	if utils.IsHost(containerID) {
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
	dm.cacheMu.Lock()
	defer dm.cacheMu.Unlock()
	if pidToServices, found := dm.containerToCloudServices.Load(containerID); found {
		if services, found := pidToServices.Load(pid); found {
			return services.names
		}
	}
	// Within the grace period the live entry wins, so once a process reusing
	// the pid resolves a cloud service, a late lookup for the exited process
	// gets the replacement's services, and a second exit replaces the retained
	// entry. Telling them apart needs a start-time identity (phase 2).
	if exited, found := dm.exitedCloudServices[exitedProcess{containerID: containerID, pid: pid}]; found {
		return exited.names
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
