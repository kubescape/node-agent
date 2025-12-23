package applicationprofile

import (
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	// DefaultPreStopCacheSize is the default maximum number of containers to track
	DefaultPreStopCacheSize = 1000
	// DefaultPreStopCacheTTL is the default time-to-live for cache entries
	DefaultPreStopCacheTTL = 5 * time.Minute
)

// PreStopHookCache tracks which containers have had their preStop hook triggered.
// It uses an LRU cache with time-based expiration to automatically clean up
// old entries and limit memory usage.
type PreStopHookCache struct {
	cache *expirable.LRU[string, struct{}]
	mu    sync.RWMutex
}

var (
	globalPreStopCache     *PreStopHookCache
	globalPreStopCacheOnce sync.Once
)

// GetPreStopHookCache returns the global preStop hook cache singleton.
// The cache is lazily initialized with default settings on first call.
func GetPreStopHookCache() *PreStopHookCache {
	globalPreStopCacheOnce.Do(func() {
		globalPreStopCache = NewPreStopHookCache(DefaultPreStopCacheSize, DefaultPreStopCacheTTL)
	})
	return globalPreStopCache
}

// NewPreStopHookCache creates a new preStop hook cache with the specified
// maximum size and TTL duration.
func NewPreStopHookCache(maxSize int, ttl time.Duration) *PreStopHookCache {
	if maxSize <= 0 {
		maxSize = DefaultPreStopCacheSize
	}
	if ttl <= 0 {
		ttl = DefaultPreStopCacheTTL
	}

	cache := expirable.NewLRU[string, struct{}](maxSize, nil, ttl)

	return &PreStopHookCache{
		cache: cache,
	}
}

// MarkPreStopTriggered marks that the preStop hook was triggered for the given container ID.
// The entry will automatically expire after the cache's TTL duration.
func (c *PreStopHookCache) MarkPreStopTriggered(containerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Add(containerID, struct{}{})
}

// WasPreStopTriggered returns true if the preStop hook was triggered for the given
// container ID and the entry has not yet expired.
func (c *PreStopHookCache) WasPreStopTriggered(containerID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, found := c.cache.Get(containerID)
	return found
}

// Remove removes a container ID from the cache.
func (c *PreStopHookCache) Remove(containerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Remove(containerID)
}

// Len returns the current number of entries in the cache.
func (c *PreStopHookCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache.Len()
}
