package rulestate

import (
	"context"
	"hash/fnv"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
)

const shardCount = 16

type entryKey struct{ ruleID, name, key string }

type bucket struct {
	entries map[entryKey]*Entry
}

type shard struct {
	mu     sync.RWMutex
	scopes map[string]*bucket
}

// Store is a bounded, TTL-expiring set of Entries sharded by scope ID.
//
// Sharding by scope ID (not by full key) is deliberate: it makes the per-scope
// cap a plain len(), makes container-removal purge a single map delete, and keeps
// one container's write churn off its neighbours' locks.
type Store struct {
	cfg     Config
	metrics Metrics
	shards  [shardCount]*shard

	sizeMu sync.Mutex
	size   int
}

func NewStore(cfg Config, metrics Metrics) *Store {
	s := &Store{cfg: cfg, metrics: metrics}
	for i := range s.shards {
		s.shards[i] = &shard{scopes: make(map[string]*bucket)}
	}
	return s
}

func (s *Store) shardFor(scopeID string) *shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(scopeID))
	return s.shards[h.Sum32()%shardCount]
}

func (s *Store) scopeCap(scopeID string) int {
	if IsHostScopeID(scopeID) {
		return s.cfg.MaxEntriesForHost
	}
	return s.cfg.MaxEntriesPerContainer
}

// Set stores e, replacing any live entry with the same (ruleID, name, key) in the
// same scope -- last write wins, which also resets the TTL.
func (s *Store) Set(e *Entry) error {
	if !s.cfg.Enabled {
		return nil
	}

	// The global check is deliberately not atomic with the insert below: it is a
	// backstop, and serialising every write on one lock to make the ceiling exact
	// would cost more than the few entries of overshoot it prevents. Concurrent
	// writers can each pass this check before any of them increments, so the size
	// can exceed MaxSize by up to the number of in-flight writers. The per-scope
	// cap, which IS exact, is what bounds any single workload.
	if s.currentSize() >= s.cfg.MaxSize {
		if s.Sweep() == 0 {
			s.metrics.ReportStateWriteRejected(e.RuleID, "global_cap")
			return ErrGlobalCapReached
		}
	}

	sh := s.shardFor(e.ScopeID)
	k := entryKey{e.RuleID, e.Name, e.Key}

	sh.mu.Lock()
	b, ok := sh.scopes[e.ScopeID]
	if !ok {
		b = &bucket{entries: make(map[entryKey]*Entry)}
		sh.scopes[e.ScopeID] = b
	}
	// Replacing an existing key does not grow the scope, so the cap must not
	// block it -- otherwise a full scope could never update its own markers.
	_, replacing := b.entries[k]
	if !replacing && len(b.entries) >= s.scopeCap(e.ScopeID) {
		sh.mu.Unlock()
		s.metrics.ReportStateWriteRejected(e.RuleID, "scope_cap")
		return ErrScopeCapReached
	}
	b.entries[k] = e
	sh.mu.Unlock()

	if !replacing {
		s.addSize(1)
	}
	s.metrics.ReportStateWrite(e.RuleID, "ok")
	return nil
}

// Get returns a live entry, or false if absent or expired. Expiry is enforced
// here as well as by the sweeper so a read never sees a stale marker.
func (s *Store) Get(ruleID string, _ armotypes.StateScope, scopeID, name, key string) (*Entry, bool) {
	if !s.cfg.Enabled {
		return nil, false
	}
	sh := s.shardFor(scopeID)

	sh.mu.RLock()
	b, ok := sh.scopes[scopeID]
	if !ok {
		sh.mu.RUnlock()
		return nil, false
	}
	e, ok := b.entries[entryKey{ruleID, name, key}]
	sh.mu.RUnlock()

	if !ok || e.expired(time.Now()) {
		return nil, false
	}
	return e, true
}

// PurgeScope drops every entry for a scope. Called on container removal.
func (s *Store) PurgeScope(scopeID string) {
	sh := s.shardFor(scopeID)
	sh.mu.Lock()
	n := 0
	if b, ok := sh.scopes[scopeID]; ok {
		n = len(b.entries)
		delete(sh.scopes, scopeID)
	}
	sh.mu.Unlock()

	if n > 0 {
		s.addSize(-n)
		s.metrics.ReportStatePurged(n)
	}
}

// Sweep removes expired entries and returns how many it reclaimed. Lazy
// expiry on read hides stale entries; only Sweep frees the memory.
func (s *Store) Sweep() int {
	now := time.Now()
	total := 0
	for _, sh := range s.shards {
		sh.mu.Lock()
		for scopeID, b := range sh.scopes {
			for k, e := range b.entries {
				if e.expired(now) {
					delete(b.entries, k)
					total++
				}
			}
			if len(b.entries) == 0 {
				delete(sh.scopes, scopeID)
			}
		}
		sh.mu.Unlock()
	}
	if total > 0 {
		s.addSize(-total)
		s.metrics.ReportStateExpired(total)
	}
	return total
}

// Run sweeps until ctx is cancelled.
func (s *Store) Run(ctx context.Context) {
	if !s.cfg.Enabled || s.cfg.SweepInterval <= 0 {
		return
	}
	t := time.NewTicker(s.cfg.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

func (s *Store) Len() int { return s.currentSize() }

func (s *Store) currentSize() int {
	s.sizeMu.Lock()
	defer s.sizeMu.Unlock()
	return s.size
}

func (s *Store) addSize(d int) {
	s.sizeMu.Lock()
	s.size += d
	s.sizeMu.Unlock()
}
