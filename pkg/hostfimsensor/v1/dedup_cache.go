package hostfimsensor

import (
	"fmt"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	fimtypes "github.com/kubescape/node-agent/pkg/hostfimsensor"
)

// dedupCache handles de-duplication of FIM events
type dedupCache struct {
	mu           sync.RWMutex
	cache        map[string]time.Time // key: "path:operation", value: timestamp
	maxSize      int
	timeWindow   time.Duration
	cleanupTimer *time.Timer
	stopChan     chan struct{}
	wg           sync.WaitGroup
}

// eventKey generates a unique key for an event based on path and operation
func eventKey(path string, operation fimtypes.FimEventType) string {
	return fmt.Sprintf("%s:%s", path, operation)
}

// newDedupCache creates a new de-duplication cache
func newDedupCache(timeWindow time.Duration, maxSize int) *dedupCache {
	return &dedupCache{
		cache:      make(map[string]time.Time),
		maxSize:    maxSize,
		timeWindow: timeWindow,
		stopChan:   make(chan struct{}),
	}
}

// start begins the de-duplication cache cleanup routine
func (dc *dedupCache) start() {
	dc.wg.Add(1)
	go dc.run()
}

// stop stops the de-duplication cache and waits for it to finish
func (dc *dedupCache) stop() {
	close(dc.stopChan)
	dc.wg.Wait()
}

// run is the main loop for the de-duplication cache cleanup
func (dc *dedupCache) run() {
	defer dc.wg.Done()

	dc.cleanupTimer = time.NewTimer(dc.timeWindow)
	defer dc.cleanupTimer.Stop()

	for {
		select {
		case <-dc.cleanupTimer.C:
			dc.cleanup()
			dc.cleanupTimer.Reset(dc.timeWindow)
		case <-dc.stopChan:
			return
		}
	}
}

// cleanup removes expired entries from the cache
func (dc *dedupCache) cleanup() {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	now := time.Now()
	expiredKeys := make([]string, 0)

	for key, timestamp := range dc.cache {
		if now.Sub(timestamp) > dc.timeWindow {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(dc.cache, key)
	}

	if len(expiredKeys) > 0 {
		logger.L().Debug("FIM dedup cache cleanup", helpers.Int("expired", len(expiredKeys)), helpers.Int("remaining", len(dc.cache)))
	}
}

// isDuplicate checks if an event is a duplicate and updates the cache
func (dc *dedupCache) isDuplicate(path string, operation fimtypes.FimEventType) bool {
	if dc == nil {
		logger.L().Debug("FIM dedup cache is nil, skipping deduplication")
		return false
	}

	key := eventKey(path, operation)
	now := time.Now()

	dc.mu.Lock()
	defer dc.mu.Unlock()

	// Check if this event exists in cache
	if lastSeen, exists := dc.cache[key]; exists {
		if now.Sub(lastSeen) <= dc.timeWindow {
			// Event is within time window, it's a duplicate
			logger.L().Debug("FIM event duplicate detected",
				helpers.String("path", path),
				helpers.String("operation", string(operation)),
				helpers.String("timeSinceLast", now.Sub(lastSeen).String()))
			return true
		}
	}

	// Add or update the event in cache
	dc.cache[key] = now
	logger.L().Debug("FIM event added to cache",
		helpers.String("path", path),
		helpers.String("operation", string(operation)),
		helpers.Int("cacheSize", len(dc.cache)))

	// If cache is full, remove oldest entry (simple FIFO approach)
	if len(dc.cache) > dc.maxSize {
		// Find and remove the oldest entry
		var oldestKey string
		var oldestTime time.Time
		first := true

		for key, timestamp := range dc.cache {
			if first || timestamp.Before(oldestTime) {
				oldestKey = key
				oldestTime = timestamp
				first = false
			}
		}

		if oldestKey != "" {
			delete(dc.cache, oldestKey)
			logger.L().Debug("FIM dedup cache evicted oldest entry", helpers.String("key", oldestKey))
		}
	}

	return false
}
