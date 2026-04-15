// Package dedupcache provides a lock-free, fixed-size deduplication cache
// for high-throughput eBPF event filtering before CEL rule evaluation.
package dedupcache

import (
	"sync/atomic"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// DedupCache is a lock-free, fixed-size deduplication cache.
// Each slot packs a 48-bit key and 16-bit expiry bucket into a single atomic uint64.
// Concurrent access from thousands of goroutines is safe without mutexes —
// benign races only cause missed dedup (safe direction), never false dedup.
type DedupCache struct {
	slots []atomic.Uint64
	mask  uint64
}

// NewDedupCache creates a cache with 2^slotsExponent slots.
// Each slot is 8 bytes; e.g. exponent 18 = 262,144 slots = 2 MB.
// slotsExponent is clamped to [10, 30] (1 KB to 8 GB).
func NewDedupCache(slotsExponent uint8) *DedupCache {
	const minExponent, maxExponent, defaultExponent = 10, 30, 18
	if slotsExponent < minExponent || slotsExponent > maxExponent {
		logger.L().Warning("slotsExponent out of range, using default",
			helpers.Int("requested", int(slotsExponent)),
			helpers.Int("default", defaultExponent))
		slotsExponent = defaultExponent
	}
	size := uint64(1) << slotsExponent
	return &DedupCache{
		slots: make([]atomic.Uint64, size),
		mask:  size - 1,
	}
}

// pack stores the upper 48 bits of key and 16-bit expiry bucket in one uint64.
func pack(key uint64, expiryBucket uint16) uint64 {
	return (key & 0xFFFFFFFFFFFF0000) | uint64(expiryBucket)
}

// unpack extracts the 48-bit key portion and 16-bit expiry bucket.
func unpack(packed uint64) (keyBits uint64, expiryBucket uint16) {
	return packed & 0xFFFFFFFFFFFF0000, uint16(packed)
}

// CheckAndSet returns true if the key is already present and not expired (duplicate).
// Otherwise it inserts the key with expiry = currentBucket + ttlBuckets and returns false.
func (c *DedupCache) CheckAndSet(key uint64, ttlBuckets uint16, currentBucket uint16) bool {
	idx := key & c.mask

	stored := c.slots[idx].Load()
	storedKey, storedExpiry := unpack(stored)
	if storedKey == (key & 0xFFFFFFFFFFFF0000) && int16(storedExpiry-currentBucket) > 0 {
		return true // duplicate
	}

	c.slots[idx].Store(pack(key, currentBucket+ttlBuckets))
	return false
}
