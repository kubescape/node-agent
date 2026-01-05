package applicationprofile

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPreStopHookCache_MarkAndCheck(t *testing.T) {
	cache := NewPreStopHookCache(100, time.Minute)

	// Initially, container should not be marked
	assert.False(t, cache.WasPreStopTriggered("container-1"))

	// Mark container as preStop triggered
	cache.MarkPreStopTriggered("container-1")

	// Now it should return true
	assert.True(t, cache.WasPreStopTriggered("container-1"))

	// Other containers should still return false
	assert.False(t, cache.WasPreStopTriggered("container-2"))
}

func TestPreStopHookCache_MultipleContainers(t *testing.T) {
	cache := NewPreStopHookCache(100, time.Minute)

	containers := []string{"container-1", "container-2", "container-3"}

	// Mark all containers
	for _, c := range containers {
		cache.MarkPreStopTriggered(c)
	}

	// All should be marked
	for _, c := range containers {
		assert.True(t, cache.WasPreStopTriggered(c), "container %s should be marked", c)
	}

	// Unmarked container should return false
	assert.False(t, cache.WasPreStopTriggered("container-4"))

	// Verify length
	assert.Equal(t, 3, cache.Len())
}

func TestPreStopHookCache_Remove(t *testing.T) {
	cache := NewPreStopHookCache(100, time.Minute)

	// Mark containers
	cache.MarkPreStopTriggered("container-1")
	cache.MarkPreStopTriggered("container-2")

	assert.Equal(t, 2, cache.Len())
	assert.True(t, cache.WasPreStopTriggered("container-1"))

	// Remove one container
	cache.Remove("container-1")

	assert.Equal(t, 1, cache.Len())
	assert.False(t, cache.WasPreStopTriggered("container-1"))
	assert.True(t, cache.WasPreStopTriggered("container-2"))

	// Removing non-existent container should not panic
	cache.Remove("non-existent")
	assert.Equal(t, 1, cache.Len())
}

func TestPreStopHookCache_TTLExpiration(t *testing.T) {
	// Create cache with very short TTL
	cache := NewPreStopHookCache(100, 50*time.Millisecond)

	cache.MarkPreStopTriggered("container-1")
	assert.True(t, cache.WasPreStopTriggered("container-1"))

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	// Entry should have expired - WasPreStopTriggered should return false
	// Note: Len() may not immediately reflect expired entries as the expirable LRU
	// only removes them lazily on access operations
	assert.False(t, cache.WasPreStopTriggered("container-1"))
}

func TestPreStopHookCache_LRUEviction(t *testing.T) {
	// Create cache with max size of 3
	cache := NewPreStopHookCache(3, time.Minute)

	// Add 3 containers
	cache.MarkPreStopTriggered("container-1")
	cache.MarkPreStopTriggered("container-2")
	cache.MarkPreStopTriggered("container-3")

	assert.Equal(t, 3, cache.Len())

	// Add a 4th container - should evict one of the existing containers
	cache.MarkPreStopTriggered("container-4")

	// Cache should still have max 3 entries
	assert.Equal(t, 3, cache.Len())

	// The newest entry should definitely be present
	assert.True(t, cache.WasPreStopTriggered("container-4"))

	// Count how many of the original containers are still present
	presentCount := 0
	for _, c := range []string{"container-1", "container-2", "container-3"} {
		if cache.WasPreStopTriggered(c) {
			presentCount++
		}
	}
	// Exactly one should have been evicted
	assert.Equal(t, 2, presentCount, "exactly one container should have been evicted")
}

func TestPreStopHookCache_LRUAccessOrder(t *testing.T) {
	// Create cache with max size of 3
	cache := NewPreStopHookCache(3, time.Minute)

	// Add 3 containers
	cache.MarkPreStopTriggered("container-1")
	cache.MarkPreStopTriggered("container-2")
	cache.MarkPreStopTriggered("container-3")

	// Access container-1 to make it recently used
	cache.WasPreStopTriggered("container-1")

	// Add a 4th container - should evict container-2 (least recently used)
	cache.MarkPreStopTriggered("container-4")

	assert.Equal(t, 3, cache.Len())
	assert.True(t, cache.WasPreStopTriggered("container-1"), "container-1 should NOT be evicted (recently accessed)")
	assert.False(t, cache.WasPreStopTriggered("container-2"), "container-2 should have been evicted")
	assert.True(t, cache.WasPreStopTriggered("container-3"))
	assert.True(t, cache.WasPreStopTriggered("container-4"))
}

func TestPreStopHookCache_ConcurrentAccess(t *testing.T) {
	cache := NewPreStopHookCache(1000, time.Minute)

	var wg sync.WaitGroup
	numGoroutines := 100
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				containerID := "container-" + string(rune('A'+id%26))
				cache.MarkPreStopTriggered(containerID)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				containerID := "container-" + string(rune('A'+id%26))
				cache.WasPreStopTriggered(containerID)
			}
		}(i)
	}

	// Concurrent removes
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations/10; j++ {
				containerID := "container-" + string(rune('A'+id%26))
				cache.Remove(containerID)
			}
		}(i)
	}

	wg.Wait()

	// Just verify no panics occurred and cache is in a valid state
	_ = cache.Len()
}

func TestPreStopHookCache_DefaultValues(t *testing.T) {
	// Test with zero/negative values - should use defaults
	cache := NewPreStopHookCache(0, 0)

	// Should work normally with default values
	cache.MarkPreStopTriggered("container-1")
	assert.True(t, cache.WasPreStopTriggered("container-1"))
}

func TestPreStopHookCache_RemarkContainer(t *testing.T) {
	cache := NewPreStopHookCache(100, 100*time.Millisecond)

	// Mark container
	cache.MarkPreStopTriggered("container-1")
	assert.True(t, cache.WasPreStopTriggered("container-1"))

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Re-mark the same container (should refresh TTL)
	cache.MarkPreStopTriggered("container-1")

	// Wait a bit more (total 100ms from first mark, but only 50ms from re-mark)
	time.Sleep(60 * time.Millisecond)

	// Should still be valid because TTL was refreshed
	assert.True(t, cache.WasPreStopTriggered("container-1"))
}

func TestPreStopHookCache_EmptyContainerID(t *testing.T) {
	cache := NewPreStopHookCache(100, time.Minute)

	// Empty container ID should work (edge case)
	cache.MarkPreStopTriggered("")
	assert.True(t, cache.WasPreStopTriggered(""))

	cache.Remove("")
	assert.False(t, cache.WasPreStopTriggered(""))
}

func TestGetPreStopHookCache_Singleton(t *testing.T) {
	// Note: This test verifies the singleton pattern works
	// but be aware that in actual tests the singleton may already be initialized

	cache1 := GetPreStopHookCache()
	cache2 := GetPreStopHookCache()

	// Both should return the same instance
	assert.Same(t, cache1, cache2, "GetPreStopHookCache should return the same instance")

	// Mark via one reference, check via the other
	cache1.MarkPreStopTriggered("singleton-test-container")
	assert.True(t, cache2.WasPreStopTriggered("singleton-test-container"))

	// Cleanup
	cache1.Remove("singleton-test-container")
}
