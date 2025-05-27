// Package resourcelocks provides a generic mechanism for managing per-resource locks
// to prevent concurrent modifications on resource-specific operations.
package resourcelocks

import (
	"sync"

	"github.com/goradd/maps"
)

// ResourceLocks manages per-resource mutexes to prevent concurrent modifications
type ResourceLocks struct {
	locks maps.SafeMap[string, *sync.Mutex]
}

// New creates a new ResourceLocks instance
func New() *ResourceLocks {
	return &ResourceLocks{
		locks: maps.SafeMap[string, *sync.Mutex]{},
	}
}

// GetLock returns a mutex for the given resource ID, creating one if it doesn't exist
func (rl *ResourceLocks) GetLock(resourceID string) *sync.Mutex {
	var lock *sync.Mutex
	var exists bool
	if lock, exists = rl.locks.Load(resourceID); !exists {
		lock = &sync.Mutex{}
		rl.locks.Set(resourceID, lock)
	}
	return lock
}

// WithLock executes the given function while holding the lock for the resource ID
func (rl *ResourceLocks) WithLock(resourceID string, fn func()) {
	lock := rl.GetLock(resourceID)
	lock.Lock()
	defer lock.Unlock()
	fn()
}

// WithLockAndError executes the given function while holding the lock for the resource ID
// and returns any error from the function
func (rl *ResourceLocks) WithLockAndError(resourceID string, fn func() error) error {
	lock := rl.GetLock(resourceID)
	lock.Lock()
	defer lock.Unlock()
	return fn()
}

// ReleaseLock removes the lock for the given resource ID from the internal map
// This should be called when a resource is removed to prevent memory leaks
func (rl *ResourceLocks) ReleaseLock(resourceID string) {
	rl.locks.Delete(resourceID)
}

// HasLock returns true if a lock exists for the given resource ID
func (rl *ResourceLocks) HasLock(resourceID string) bool {
	_, exists := rl.locks.Load(resourceID)
	return exists
}

// ActiveLocks returns the number of active locks being managed
func (rl *ResourceLocks) ActiveLocks() int {
	count := 0
	rl.locks.Range(func(_ string, _ *sync.Mutex) bool {
		count++
		return true
	})
	return count
}

// Clear removes all locks from the manager
// This should only be used during shutdown or testing
func (rl *ResourceLocks) Clear() {
	// Create a slice to collect keys first to avoid modifying map during iteration
	var keys []string
	rl.locks.Range(func(key string, _ *sync.Mutex) bool {
		keys = append(keys, key)
		return true
	})

	// Now delete all keys
	for _, key := range keys {
		rl.locks.Delete(key)
	}
}
