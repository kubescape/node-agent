package dnsmanager

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/goradd/maps"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

// DNSManager is used to manage DNS events and save IP resolutions.
type DNSManager struct {
	addressToDomainMap maps.SafeMap[string, string]
	lookupCache        *sync.Map          // Cache for DNS lookups
	failureCache       *sync.Map          // Cache for failed lookups to prevent repeated attempts
	cleanupTicker      *time.Ticker       // Ticker for periodic cache cleanup
	cancel             context.CancelFunc // Cancel function for cleanup goroutine
}

type cacheEntry struct {
	addresses []string
	timestamp time.Time
}

const (
	defaultPositiveTTL = 1 * time.Minute // Default TTL for successful lookups
	defaultNegativeTTL = 5 * time.Second // Default TTL for failed lookups
	cleanupInterval    = 5 * time.Minute // How often to run cache cleanup
)

var _ DNSManagerClient = (*DNSManager)(nil)
var _ DNSResolver = (*DNSManager)(nil)

func CreateDNSManager(ctx context.Context) *DNSManager {
	ctx, cancel := context.WithCancel(ctx)
	dm := &DNSManager{
		lookupCache:   &sync.Map{},
		failureCache:  &sync.Map{},
		cleanupTicker: time.NewTicker(cleanupInterval),
		cancel:        cancel,
	}

	// Start the cleanup goroutine
	go dm.cacheCleaner(ctx)

	return dm
}

func (dm *DNSManager) ReportDNSEvent(dnsEvent tracerdnstype.Event) {
	// If we have addresses in the event, use them directly
	if len(dnsEvent.Addresses) > 0 {
		for _, address := range dnsEvent.Addresses {
			dm.addressToDomainMap.Set(address, dnsEvent.DNSName)
		}

		// Update the cache with these known good addresses
		dm.lookupCache.Store(dnsEvent.DNSName, cacheEntry{
			addresses: dnsEvent.Addresses,
			timestamp: time.Now(),
		})
		return
	}

	// Check if we've recently failed to look up this domain
	if failedTime, failed := dm.failureCache.Load(dnsEvent.DNSName); failed {
		if time.Since(failedTime.(time.Time)) < defaultNegativeTTL {
			return
		}
		// Failed entry has expired, remove it
		dm.failureCache.Delete(dnsEvent.DNSName)
	}

	// Check if we have a cached result
	if cached, ok := dm.lookupCache.Load(dnsEvent.DNSName); ok {
		entry := cached.(cacheEntry)
		if time.Since(entry.timestamp) < defaultPositiveTTL {
			// Use cached addresses
			for _, addr := range entry.addresses {
				dm.addressToDomainMap.Set(addr, dnsEvent.DNSName)
			}
			return
		}
	}

	// Only perform lookup if we don't have cached results
	addresses, err := net.LookupIP(dnsEvent.DNSName)
	if err != nil {
		// Cache the failure
		dm.failureCache.Store(dnsEvent.DNSName, time.Now())
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
	dm.lookupCache.Store(dnsEvent.DNSName, cacheEntry{
		addresses: addrStrings,
		timestamp: time.Now(),
	})
}

// cacheCleaner runs periodically to clean up expired entries from both caches
func (dm *DNSManager) cacheCleaner(ctx context.Context) {
	for {
		select {
		case <-dm.cleanupTicker.C:
			now := time.Now()

			// Clean up positive cache
			dm.lookupCache.Range(func(key, value interface{}) bool {
				entry := value.(cacheEntry)
				if now.Sub(entry.timestamp) > defaultPositiveTTL {
					dm.lookupCache.Delete(key)
				}
				return true
			})

			// Clean up negative cache
			dm.failureCache.Range(func(key, value interface{}) bool {
				failedTime := value.(time.Time)
				if now.Sub(failedTime) > defaultNegativeTTL {
					dm.failureCache.Delete(key)
				}
				return true
			})

		case <-ctx.Done():
			dm.cleanupTicker.Stop()
			return
		}
	}
}

func (dm *DNSManager) ResolveIPAddress(ipAddr string) (string, bool) {
	domain := dm.addressToDomainMap.Get(ipAddr)
	return domain, domain != ""
}
