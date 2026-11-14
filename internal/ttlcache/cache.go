// Package ttlcache provides an experimental passive, fixed-TTL LRU cache.
// It starts no goroutines. Expired entries are unreadable immediately, but can
// retain references until a subsequent write, Len, DeleteAll, or disposal.
package ttlcache

import (
	"container/list"
	"sync"
	"time"

	jellycache "github.com/jellydator/ttlcache/v3"
)

// Cache uses jellydator for TTL checks and read recency. The oldest write has
// the earliest deadline because Get never extends TTL. Keep write order
// independently so one Set can reclaim one expired slot, regardless of recency.
type Cache[K comparable, V any] struct {
	mu       sync.Mutex
	cache    *jellycache.Cache[K, V]
	capacity int
	writes   list.List // oldest first, elements contain *jellycache.Item[K, V]
	byKey    map[K]*list.Element
}

// New creates a cache. Nonpositive capacity means unlimited and nonpositive
// TTL means no expiration.
func New[K comparable, V any](capacity int, ttl time.Duration) *Cache[K, V] {
	if ttl <= 0 {
		ttl = jellycache.NoTTL
	}
	return &Cache[K, V]{
		capacity: capacity,
		byKey:    make(map[K]*list.Element),
		cache: jellycache.New[K, V](
			jellycache.WithTTL[K, V](ttl),
			jellycache.WithDisableTouchOnHit[K, V](),
		),
	}
}

// Get returns a live value and promotes its LRU position without renewing TTL.
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if item := c.cache.Get(key); item != nil {
		return item.Value(), true
	}
	var zero V
	return zero, false
}

func (c *Cache[K, V]) remove(key K) {
	c.cache.Delete(key)
	if elem := c.byKey[key]; elem != nil {
		c.writes.Remove(elem)
		delete(c.byKey, key)
	}
}

func (c *Cache[K, V]) removeExpired() bool {
	if elem := c.writes.Front(); elem != nil {
		item := elem.Value.(*jellycache.Item[K, V])
		if item.IsExpired() {
			c.remove(item.Key())
			return true
		}
	}
	return false
}

// Set renews expiration and reclaims at most one expired entry per write.
func (c *Cache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeExpired()
	if elem := c.byKey[key]; elem != nil {
		c.cache.Set(key, value, jellycache.DefaultTTL)
		c.writes.MoveToBack(elem)
		return
	}
	if c.capacity > 0 && len(c.byKey) == c.capacity {
		// A deadline can pass between the expiry check and the LRU lookup.
		// Recheck before evicting a live victim. If all entries have since
		// expired, RangeBackwards skips them and removeExpired opens a slot.
		victim := c.writes.Front().Value.(*jellycache.Item[K, V]).Key()
		c.cache.RangeBackwards(func(item *jellycache.Item[K, V]) bool {
			victim = item.Key()
			return false
		})
		if !c.removeExpired() {
			c.remove(victim)
		}
	}
	item := c.cache.Set(key, value, jellycache.DefaultTTL)
	c.byKey[key] = c.writes.PushBack(item)
}

// Has rejects expired entries without updating recency or expiration.
func (c *Cache[K, V]) Has(key K) bool { return c.cache.Has(key) }

// Delete removes a key, if present.
func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remove(key)
}

// DeleteAll releases all retained entries.
func (c *Cache[K, V]) DeleteAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.DeleteAll()
	clear(c.byKey)
	c.writes.Init()
}

// Len reclaims expired entries and reports the live count.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.removeExpired() {
	}
	return len(c.byKey)
}
