package rulestate

import (
	"context"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

const shardCount = 16

// defaultWriteSweepInterval bounds write-path sweeping when no sweep interval is
// configured, so a missing setting cannot reinstate the per-write full walk.
const defaultWriteSweepInterval = time.Second

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

	// size is atomic rather than mutex-guarded: it is read on every write, and a
	// single global mutex there would serialise exactly what the sharding exists
	// to keep independent.
	size atomic.Int64

	// lastSweepNs bounds how often the WRITE path may sweep. Without it, every
	// write at the ceiling triggers a full all-shard walk -- see sweepIfDue.
	lastSweepNs atomic.Int64
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

// scopeCap picks the cap for a bucket.
//
// The larger cap applies to the two node-wide buckets -- the host
// pseudo-container and node scope itself. Neither holds one workload: they are
// shared by every rule and every process on the node, and neither is ever
// reclaimed by PurgeScope, so both rely on TTL and need the headroom. Bounding
// node scope by the per-container cap would starve it far sooner than intended on
// a busy node.
//
// Pod scope deliberately takes the per-container cap. A pod is a single workload,
// like a container, and it IS reclaimed -- RuleManager purges the bucket once the
// pod's last container is gone. Note the cap is shared by every container in the
// pod, so a pod-scoped rule in a many-container pod has less room per container
// than a container-scoped one; that is intended, because pod scope exists for
// facts about the pod as a unit rather than per-process markers. If a real
// workload ever needs more, state_write_rejected_total{reason="scope_cap"} is
// what says so.
func (s *Store) scopeCap(scopeID string) int {
	if IsHostScopeID(scopeID) || scopeID == NodeScopeID() {
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
	sh := s.shardFor(e.ScopeID)
	k := entryKey{e.RuleID, e.Name, e.Key}

	if s.currentSize() >= s.cfg.MaxSize {
		if s.sweepIfDue() == 0 {
			// A replacement does not grow the store, so the ceiling must not block
			// it -- the same reasoning the per-scope cap already applies below.
			// Otherwise a rule loses the ability to refresh an established marker
			// exactly when the store is under most pressure, which is when an
			// incident is most likely to be in progress.
			//
			// The peek costs an extra RLock, but only on this already-degraded
			// path: at the ceiling with nothing reclaimable. The hot path is
			// unchanged.
			if !s.holds(sh, e.ScopeID, k) {
				s.metrics.ReportStateWriteRejected(e.RuleID, "global_cap")
				return ErrGlobalCapReached
			}
		}
	}

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

// holds reports whether a live-or-expired entry already exists under k. Used only
// by the global-cap path to tell a replacement from a genuine insert.
func (s *Store) holds(sh *shard, scopeID string, k entryKey) bool {
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	b, ok := sh.scopes[scopeID]
	if !ok {
		return false
	}
	_, exists := b.entries[k]
	return exists
}

// Get returns a live entry, or false if absent or expired. Expiry is enforced
// here as well as by the sweeper so a read never sees a stale marker.
//
// It takes no scope: the scope is already encoded in scopeID's type prefix, and a
// second, ignored scope argument on the read path of a scope-keyed store invites a
// caller to pass one that disagrees and assume it is checked.
func (s *Store) Get(ruleID, scopeID, name, key string) (*Entry, bool) {
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
//
// It is also where the per-kind occupancy gauge is published: the walk already
// visits every surviving bucket under the lock, so the counts are free here and
// would need a second full traversal anywhere else.
func (s *Store) Sweep() int {
	now := time.Now()
	s.lastSweepNs.Store(now.UnixNano())
	total := 0
	live := make(map[string]int, len(ScopeKinds()))
	for _, kind := range ScopeKinds() {
		live[kind] = 0
	}
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
				continue
			}
			live[ScopeKind(scopeID)] += len(b.entries)
		}
		sh.mu.Unlock()
	}
	// Every kind is reported, including the ones now at zero: a gauge that is
	// only written when non-zero keeps its last value forever once a kind drains.
	for kind, n := range live {
		s.metrics.ReportStateEntries(kind, n)
	}
	if total > 0 {
		s.addSize(-total)
		s.metrics.ReportStateExpired(total)
	}
	return total
}

// sweepIfDue is the write path's sweep, rate-limited to at most one per sweep
// interval across all writers.
//
// Without the limit, reaching the global ceiling turns every subsequent write
// into a full walk of all 16 shards, each under its write lock -- up to MaxSize
// (100k by default) entries examined per write, while the rule loop is
// concurrent, so every worker stalls behind it. That is a cliff exactly when the
// node is busiest, and it does not even help: if the previous sweep a moment ago
// reclaimed nothing, neither will this one.
//
// Returning 0 when a sweep is not due is the honest answer for the caller's
// purposes -- nothing was reclaimed -- so the write falls through to the
// replacement-only rule, which is the same decision it would make after a sweep
// that freed nothing.
func (s *Store) sweepIfDue() int {
	interval := s.cfg.SweepInterval
	if interval <= 0 {
		// No background sweeper is running, so the write path is the only
		// reclamation there is; keep it cheap but do not disable it.
		interval = defaultWriteSweepInterval
	}
	last := s.lastSweepNs.Load()
	now := time.Now().UnixNano()
	if now-last < int64(interval) {
		return 0
	}
	// CAS so that concurrent writers at the ceiling produce one sweep, not one
	// per writer.
	if !s.lastSweepNs.CompareAndSwap(last, now) {
		return 0
	}
	return s.Sweep()
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

func (s *Store) currentSize() int { return int(s.size.Load()) }

func (s *Store) addSize(d int) { s.size.Add(int64(d)) }
