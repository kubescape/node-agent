package dedupcache

import (
	"sync"
	"testing"
)

func TestCheckAndSet_BasicInsertAndLookup(t *testing.T) {
	c := NewDedupCache(10) // 1024 slots

	key := uint64(0xDEADBEEF12340000)
	ttl := uint16(156) // ~10s in 64ms buckets
	now := uint16(1000)

	// First call: not a duplicate
	if c.CheckAndSet(key, ttl, now) {
		t.Fatal("expected false on first insert")
	}

	// Second call: duplicate
	if !c.CheckAndSet(key, ttl, now) {
		t.Fatal("expected true on second lookup")
	}
}

func TestCheckAndSet_TTLExpiry(t *testing.T) {
	c := NewDedupCache(10)

	key := uint64(0xABCDABCD00000000)
	ttl := uint16(10) // expires at bucket 1010
	now := uint16(1000)

	c.CheckAndSet(key, ttl, now)

	// Still within TTL (bucket 1009 < expiry 1010)
	if !c.CheckAndSet(key, ttl, uint16(1009)) {
		t.Fatal("expected duplicate within TTL")
	}

	// Exactly at expiry boundary (1010 is NOT > 1010, so expired)
	if c.CheckAndSet(key, ttl, uint16(1010)) {
		t.Fatal("expected not duplicate at expiry boundary")
	}

	// After expiry
	if c.CheckAndSet(key, ttl, uint16(1100)) {
		t.Fatal("expected not duplicate after expiry")
	}
}

func TestCheckAndSet_SlotCollision(t *testing.T) {
	c := NewDedupCache(10) // mask = 1023

	// Two different keys that map to the same slot but have different upper 48 bits
	key1 := uint64(0xAAAA000000000100) // slot = 0x100 & 0x3FF = 256
	key2 := uint64(0xBBBB000000000100) // slot = 0x100 & 0x3FF = 256, different upper bits

	ttl := uint16(156)
	now := uint16(1000)

	c.CheckAndSet(key1, ttl, now)

	// key2 overwrites key1's slot — not a duplicate
	if c.CheckAndSet(key2, ttl, now) {
		t.Fatal("expected false for different key in same slot")
	}

	// key1 is now evicted — not found
	if c.CheckAndSet(key1, ttl, now) {
		t.Fatal("expected false for evicted key")
	}
}

func TestCheckAndSet_PackUnpack(t *testing.T) {
	key := uint64(0xDEADBEEFCAFE0000)
	expiry := uint16(42)

	packed := pack(key, expiry)
	gotKey, gotExpiry := unpack(packed)

	if gotKey != (key & 0xFFFFFFFFFFFF0000) {
		t.Fatalf("key mismatch: got %x, want %x", gotKey, key&0xFFFFFFFFFFFF0000)
	}
	if gotExpiry != expiry {
		t.Fatalf("expiry mismatch: got %d, want %d", gotExpiry, expiry)
	}
}

func TestCheckAndSet_ConcurrentHammer(t *testing.T) {
	c := NewDedupCache(14) // 16384 slots

	const goroutines = 100
	const opsPerGoroutine = 10000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				key := uint64(id*opsPerGoroutine+i) << 16
				c.CheckAndSet(key, 156, uint16(1000))
			}
		}(g)
	}

	wg.Wait()
	// No panics or data races = success (run with -race)
}

func BenchmarkCheckAndSet(b *testing.B) {
	c := NewDedupCache(18) // production size

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := uint64(i) << 16
		c.CheckAndSet(key, 156, uint16(1000))
	}
}

func BenchmarkCheckAndSet_Hit(b *testing.B) {
	c := NewDedupCache(18)
	key := uint64(0xDEADBEEF00000000)
	c.CheckAndSet(key, 156, uint16(1000))

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.CheckAndSet(key, 156, uint16(1000))
	}
}
