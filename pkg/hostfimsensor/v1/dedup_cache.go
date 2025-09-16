package hostfimsensor

import (
	"fmt"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	fimtypes "github.com/kubescape/node-agent/pkg/hostfimsensor"
)

// dedupCache handles de-duplication of FIM events using expirable.LRU
type dedupCache struct {
	cache      *expirable.LRU[string, time.Time] // key: "path:operation", value: timestamp
	maxSize    int
	timeWindow time.Duration
}

// eventKey generates a unique key for an event based on path and operation
func eventKey(path string, operation fimtypes.FimEventType) string {
	return fmt.Sprintf("%s:%s", path, operation)
}

// newDedupCache creates a new de-duplication cache
func newDedupCache(timeWindow time.Duration, maxSize int) *dedupCache {
	// Create expirable LRU cache with TTL equal to timeWindow
	cache := expirable.NewLRU[string, time.Time](maxSize, nil, timeWindow)

	return &dedupCache{
		cache:      cache,
		maxSize:    maxSize,
		timeWindow: timeWindow,
	}
}

// start begins the de-duplication cache cleanup routine
func (dc *dedupCache) start() {
	// No-op: expirable.LRU handles cleanup automatically
}

// stop stops the de-duplication cache and waits for it to finish
func (dc *dedupCache) stop() {
	// No-op: expirable.LRU handles cleanup automatically
}

// isDuplicate checks if an event is a duplicate and updates the cache
func (dc *dedupCache) isDuplicate(path string, operation fimtypes.FimEventType) bool {
	if dc == nil {
		logger.L().Debug("FIM dedup cache is nil, skipping deduplication")
		return false
	}

	key := eventKey(path, operation)
	now := time.Now()

	// Check if this event exists in cache
	if lastSeen, exists := dc.cache.Get(key); exists {
		// Event exists and hasn't expired (expirable.LRU handles expiration)
		logger.L().Debug("FIM event duplicate detected",
			helpers.String("path", path),
			helpers.String("operation", string(operation)),
			helpers.String("timeSinceLast", now.Sub(lastSeen).String()))
		return true
	}

	// Add the event to cache (expirable.LRU will handle expiration and eviction)
	dc.cache.Add(key, now)

	return false
}
