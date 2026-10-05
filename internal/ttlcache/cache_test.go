package ttlcache

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func waitUntilExpired(deadline time.Time) {
	time.Sleep(time.Until(deadline) + time.Millisecond)
}

func TestExpirationAndRenewal(t *testing.T) {
	c := New[string, int](3, 80*time.Millisecond)
	c.Set("a", 1)
	deadline := c.cache.Get("a").ExpiresAt()
	require.True(t, c.Has("a"))
	value, found := c.Get("a")
	require.True(t, found)
	require.Equal(t, 1, value)
	require.Equal(t, deadline, c.cache.Get("a").ExpiresAt(), "Get and Has must not renew TTL")
	waitUntilExpired(deadline)
	require.False(t, c.Has("a"))
	_, found = c.Get("a")
	require.False(t, found)
	require.Zero(t, c.Len())

	c.Set("a", 2)
	deadline = c.cache.Get("a").ExpiresAt()
	time.Sleep(5 * time.Millisecond)
	c.Set("a", 3)
	renewed := c.cache.Get("a").ExpiresAt()
	require.True(t, renewed.After(deadline))
	value, found = c.Get("a")
	require.True(t, found)
	require.Equal(t, 3, value)
}

func TestRecency(t *testing.T) {
	t.Run("Get promotes", func(t *testing.T) {
		c := New[string, int](2, time.Minute)
		c.Set("a", 1)
		c.Set("b", 2)
		_, _ = c.Get("a")
		c.Set("c", 3)
		require.True(t, c.Has("a"))
		require.False(t, c.Has("b"))
		require.Equal(t, 2, c.Len())
	})
	t.Run("Has does not promote", func(t *testing.T) {
		c := New[string, int](2, time.Minute)
		c.Set("a", 1)
		c.Set("b", 2)
		require.True(t, c.Has("a"))
		c.Set("c", 3)
		require.False(t, c.Has("a"))
		require.True(t, c.Has("b"))
	})
}

func TestExpiredRecentEntryIsReclaimedBeforeLiveEviction(t *testing.T) {
	c := New[string, int](2, time.Minute)
	c.Set("live", 1)
	// Make the expired entry more recent than the live one. A plain Set without
	// DeleteExpired would evict "live" when inserting "new".
	c.cache.Set("expired", 2, time.Millisecond)
	waitUntilExpired(c.cache.Get("expired").ExpiresAt())
	c.Set("new", 3)
	require.True(t, c.Has("live"))
	require.True(t, c.Has("new"))
	require.False(t, c.Has("expired"))
	require.Equal(t, 2, c.Len())
}

func TestZeroNilDeleteAndClear(t *testing.T) {
	c := New[string, *int](2, time.Minute)
	c.Set("nil", nil)
	value, found := c.Get("nil")
	require.True(t, found)
	require.Nil(t, value)
	c.Delete("missing")
	c.Delete("nil")
	require.False(t, c.Has("nil"))
	c.Set("nil", nil)
	c.DeleteAll()
	require.Zero(t, c.Len())
	zero := New[string, int](1, time.Minute)
	zero.Set("zero", 0)
	v, found := zero.Get("zero")
	require.True(t, found)
	require.Zero(t, v)
}

func TestNonpositiveCapacityAndTTL(t *testing.T) {
	for _, capacity := range []int{0, -1} {
		for _, ttl := range []time.Duration{0, -time.Second} {
			c := New[int, int](capacity, ttl)
			for i := range 100 {
				c.Set(i, i)
			}
			require.Equal(t, 100, c.Len())
			require.True(t, c.cache.Get(0).ExpiresAt().IsZero())
		}
	}
}

func TestConcurrentOperations(t *testing.T) {
	c := New[int, int](100, time.Millisecond)
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				key := (i + worker) % 200
				switch i % 6 {
				case 0:
					c.Set(key, i)
				case 1:
					_, _ = c.Get(key)
				case 2:
					_ = c.Has(key)
				case 3:
					c.Delete(key)
				case 4:
					_ = c.Len()
				case 5:
					c.DeleteAll()
				}
			}
		}()
	}
	wg.Wait()
	require.LessOrEqual(t, c.Len(), 100)
}

func TestConstructionAndDiscardStartsNoGoroutines(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for range 1000 {
		c := New[int, int](10, time.Millisecond)
		c.Set(1, 1)
	}
}
