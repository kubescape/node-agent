package resourcelocks

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	cl := New()
	assert.NotNil(t, cl)
	assert.Equal(t, 0, cl.ActiveLocks())
}

func TestGetLock(t *testing.T) {
	cl := New()
	containerID := "test-container-1"

	// First call should create a new lock
	lock1 := cl.GetLock(containerID)
	assert.NotNil(t, lock1)
	assert.True(t, cl.HasLock(containerID))
	assert.Equal(t, 1, cl.ActiveLocks())

	// Second call should return the same lock
	lock2 := cl.GetLock(containerID)
	assert.Same(t, lock1, lock2)
	assert.Equal(t, 1, cl.ActiveLocks())

	// Different container should get different lock
	differentContainerID := "test-container-2"
	lock3 := cl.GetLock(differentContainerID)
	assert.NotNil(t, lock3)
	assert.NotSame(t, lock1, lock3)
	assert.Equal(t, 2, cl.ActiveLocks())
}

func TestWithLock(t *testing.T) {
	cl := New()
	containerID := "test-container"
	executed := false

	cl.WithLock(containerID, func() {
		executed = true
	})

	assert.True(t, executed)
	assert.True(t, cl.HasLock(containerID))
}

func TestWithLockAndError(t *testing.T) {
	cl := New()
	containerID := "test-container"

	// Test successful execution
	executed := false
	err := cl.WithLockAndError(containerID, func() error {
		executed = true
		return nil
	})

	assert.True(t, executed)
	assert.NoError(t, err)

	// Test error return
	testError := errors.New("test error")
	err = cl.WithLockAndError(containerID, func() error {
		return testError
	})

	assert.Equal(t, testError, err)
}

func TestReleaseLock(t *testing.T) {
	cl := New()
	containerID := "test-container"

	// Create a lock
	lock := cl.GetLock(containerID)
	assert.NotNil(t, lock)
	assert.True(t, cl.HasLock(containerID))
	assert.Equal(t, 1, cl.ActiveLocks())

	// Release the lock
	cl.ReleaseLock(containerID)
	assert.False(t, cl.HasLock(containerID))
	assert.Equal(t, 0, cl.ActiveLocks())

	// Releasing non-existent lock should not panic
	cl.ReleaseLock("non-existent")
	assert.Equal(t, 0, cl.ActiveLocks())
}

func TestHasLock(t *testing.T) {
	cl := New()
	containerID := "test-container"

	// Initially should not have lock
	assert.False(t, cl.HasLock(containerID))

	// After getting lock, should return true
	cl.GetLock(containerID)
	assert.True(t, cl.HasLock(containerID))

	// After releasing, should return false
	cl.ReleaseLock(containerID)
	assert.False(t, cl.HasLock(containerID))
}

func TestActiveLocks(t *testing.T) {
	cl := New()

	assert.Equal(t, 0, cl.ActiveLocks())

	// Add some locks
	cl.GetLock("container-1")
	assert.Equal(t, 1, cl.ActiveLocks())

	cl.GetLock("container-2")
	assert.Equal(t, 2, cl.ActiveLocks())

	cl.GetLock("container-3")
	assert.Equal(t, 3, cl.ActiveLocks())

	// Getting the same lock again shouldn't increase count
	cl.GetLock("container-1")
	assert.Equal(t, 3, cl.ActiveLocks())

	// Release some locks
	cl.ReleaseLock("container-1")
	assert.Equal(t, 2, cl.ActiveLocks())

	cl.ReleaseLock("container-2")
	assert.Equal(t, 1, cl.ActiveLocks())

	cl.ReleaseLock("container-3")
	assert.Equal(t, 0, cl.ActiveLocks())
}

func TestClear(t *testing.T) {
	cl := New()

	// Add some locks
	cl.GetLock("container-1")
	cl.GetLock("container-2")
	cl.GetLock("container-3")
	assert.Equal(t, 3, cl.ActiveLocks())

	// Clear all locks
	cl.Clear()
	assert.Equal(t, 0, cl.ActiveLocks())
	assert.False(t, cl.HasLock("container-1"))
	assert.False(t, cl.HasLock("container-2"))
	assert.False(t, cl.HasLock("container-3"))

	// Clear empty map should not panic
	cl.Clear()
	assert.Equal(t, 0, cl.ActiveLocks())
}

func TestConcurrentAccess(t *testing.T) {
	cl := New()
	containerID := "test-container"
	numGoroutines := 100
	var wg sync.WaitGroup

	// Test concurrent GetLock calls
	wg.Add(numGoroutines)
	locks := make([]*sync.Mutex, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()
			locks[index] = cl.GetLock(containerID)
		}(i)
	}

	wg.Wait()

	// All locks should be the same instance
	for i := 1; i < numGoroutines; i++ {
		assert.Equal(t, locks[0], locks[i])
	}

	// Should still only have one lock
	assert.Equal(t, 1, cl.ActiveLocks())
}

func TestConcurrentWithLock(t *testing.T) {
	cl := New()
	containerID := "test-container"
	numGoroutines := 50
	var wg sync.WaitGroup
	var counter int64

	wg.Add(numGoroutines)

	// Test that WithLock properly serializes access
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			cl.WithLock(containerID, func() {
				// Simulate some work and increment counter
				current := atomic.LoadInt64(&counter)
				time.Sleep(1 * time.Millisecond) // Small delay to increase contention
				atomic.StoreInt64(&counter, current+1)
			})
		}()
	}

	wg.Wait()

	// Counter should equal the number of goroutines if locking worked properly
	assert.Equal(t, int64(numGoroutines), atomic.LoadInt64(&counter))
}

func TestConcurrentMultipleContainers(t *testing.T) {
	cl := New()
	numContainers := 10
	numGoroutinesPerContainer := 10
	var wg sync.WaitGroup
	counters := make([]int64, numContainers)

	wg.Add(numContainers * numGoroutinesPerContainer)

	// Test concurrent access to multiple containers
	for containerIndex := 0; containerIndex < numContainers; containerIndex++ {
		for goroutineIndex := 0; goroutineIndex < numGoroutinesPerContainer; goroutineIndex++ {
			go func(cIndex int) {
				defer wg.Done()
				containerID := fmt.Sprintf("container-%d", cIndex)

				cl.WithLock(containerID, func() {
					// Increment counter for this container
					current := atomic.LoadInt64(&counters[cIndex])
					time.Sleep(1 * time.Millisecond)
					atomic.StoreInt64(&counters[cIndex], current+1)
				})
			}(containerIndex)
		}
	}

	wg.Wait()

	// Each container should have been incremented the correct number of times
	for i := 0; i < numContainers; i++ {
		assert.Equal(t, int64(numGoroutinesPerContainer), atomic.LoadInt64(&counters[i]),
			"Container %d counter mismatch", i)
	}

	// Should have locks for all containers
	assert.Equal(t, numContainers, cl.ActiveLocks())
}

func TestPanicRecovery(t *testing.T) {
	cl := New()
	containerID := "test-container"

	// Test that panic in WithLock doesn't leave lock held
	assert.Panics(t, func() {
		cl.WithLock(containerID, func() {
			panic("test panic")
		})
	})

	// Lock should still be accessible after panic
	executed := false
	cl.WithLock(containerID, func() {
		executed = true
	})
	assert.True(t, executed)

	// Test panic in WithLockAndError
	assert.Panics(t, func() {
		cl.WithLockAndError(containerID, func() error {
			panic("test panic")
		})
	})
}

func TestEmptyContainerID(t *testing.T) {
	cl := New()
	emptyID := ""

	// Should work with empty container ID
	lock := cl.GetLock(emptyID)
	assert.NotNil(t, lock)
	assert.True(t, cl.HasLock(emptyID))

	executed := false
	cl.WithLock(emptyID, func() {
		executed = true
	})
	assert.True(t, executed)

	cl.ReleaseLock(emptyID)
	assert.False(t, cl.HasLock(emptyID))
}

// Benchmark tests
func BenchmarkGetLock(b *testing.B) {
	cl := New()
	containerID := "benchmark-container"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cl.GetLock(containerID)
	}
}

func BenchmarkWithLock(b *testing.B) {
	cl := New()
	containerID := "benchmark-container"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cl.WithLock(containerID, func() {
			// Empty function to measure just the locking overhead
		})
	}
}

func BenchmarkConcurrentWithLock(b *testing.B) {
	cl := New()
	containerID := "benchmark-container"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cl.WithLock(containerID, func() {
				// Empty function to measure just the locking overhead
			})
		}
	})
}

func BenchmarkMultipleContainers(b *testing.B) {
	cl := New()
	numContainers := 100

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containerID := fmt.Sprintf("container-%d", i%numContainers)
		cl.WithLock(containerID, func() {
			// Empty function
		})
	}
}
