// Package ttlcache provides passive, fixed-TTL LRU caches. It starts no
// goroutines and registers no asynchronous callbacks.
//
// Reads update LRU order without extending expiration. Expired entries are
// immediately unreadable, but their references remain until a write, Len,
// DeleteAll, or disposal. Finite capacities bound stored entry count;
// unlimited caches do not have a memory bound.
package ttlcache

import (
	"time"

	jellycache "github.com/jellydator/ttlcache/v3"
)

type Cache[K comparable, V any] struct {
	cache *jellycache.Cache[K, V]
}

// New creates a cache. Nonpositive capacity means unlimited; nonpositive TTL
// means no expiration, replacing expirable's ten-year sentinel.
func New[K comparable, V any](capacity int, ttl time.Duration) *Cache[K, V] {
	if capacity < 0 {
		capacity = 0
	}
	if ttl <= 0 {
		ttl = jellycache.NoTTL
	}
	return &Cache[K, V]{cache: jellycache.New[K, V](
		jellycache.WithCapacity[K, V](uint64(capacity)),
		jellycache.WithTTL[K, V](ttl),
		jellycache.WithDisableTouchOnHit[K, V](),
	)}
}

func (c *Cache[K, V]) Get(key K) (V, bool) {
	if item := c.cache.Get(key); item != nil {
		return item.Value(), true
	}
	var zero V
	return zero, false
}

// Set renews expiration and reclaims expired entries before capacity eviction.
func (c *Cache[K, V]) Set(key K, value V) {
	c.cache.DeleteExpired()
	c.cache.Set(key, value, jellycache.DefaultTTL)
}

// Has rejects expired entries without updating LRU order or expiration.
// Unlike expirable.Contains, it does not recognize retained expired entries.
func (c *Cache[K, V]) Has(key K) bool { return c.cache.Has(key) }

func (c *Cache[K, V]) Delete(key K) { c.cache.Delete(key) }

func (c *Cache[K, V]) DeleteAll() { c.cache.DeleteAll() }

// Len reclaims expired entries and reports live entries, rather than counting
// retained expired entries as expirable.Len does.
func (c *Cache[K, V]) Len() int {
	c.cache.DeleteExpired()
	return c.cache.Len()
}
