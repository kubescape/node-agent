package rulestate

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig() Config {
	return Config{
		Enabled:                true,
		MaxSize:                1000,
		MaxEntriesPerContainer: 4,
		MaxEntriesForHost:      8,
		MaxTTL:                 30 * time.Minute,
		SweepInterval:          time.Second,
		AncestorMaxDepth:       8,
	}
}

func entry(ruleID, scopeID, name, key string, ts time.Time, ttl time.Duration) *Entry {
	return &Entry{
		RuleID: ruleID, Name: name, Key: key,
		Scope: armotypes.StateScopeContainer, ScopeID: scopeID,
		EventType: "exec",
		Timestamp: ts, ExpiresAt: ts.Add(ttl),
		Process: &armotypes.Process{PID: 4471, Comm: "xmrig"},
	}
}

func TestStore_SetThenGet(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	now := time.Now()
	require.NoError(t, s.Set(entry("R1089", "c:abc", "mount_exec", "4471", now, time.Minute)))

	got, ok := s.Get("R1089", armotypes.StateScopeContainer, "c:abc", "mount_exec", "4471")
	require.True(t, ok)
	assert.Equal(t, uint32(4471), got.Process.PID)
}

func TestStore_IsolationAcrossRulesScopesAndKeys(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	now := time.Now()
	require.NoError(t, s.Set(entry("R1089", "c:abc", "mount_exec", "4471", now, time.Minute)))

	// Different rule: state is rule-private.
	_, ok := s.Get("R1090", armotypes.StateScopeContainer, "c:abc", "mount_exec", "4471")
	assert.False(t, ok, "another rule must not see this entry")

	// Different container: the security property.
	_, ok = s.Get("R1089", armotypes.StateScopeContainer, "c:def", "mount_exec", "4471")
	assert.False(t, ok, "a neighbouring container must not see this entry")

	// Different key and different name.
	_, ok = s.Get("R1089", armotypes.StateScopeContainer, "c:abc", "mount_exec", "9999")
	assert.False(t, ok)
	_, ok = s.Get("R1089", armotypes.StateScopeContainer, "c:abc", "other", "4471")
	assert.False(t, ok)
}

func TestStore_ExpiredEntryIsAMissOnRead(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	past := time.Now().Add(-2 * time.Minute)
	require.NoError(t, s.Set(entry("R1089", "c:abc", "mount_exec", "4471", past, time.Minute)))

	_, ok := s.Get("R1089", armotypes.StateScopeContainer, "c:abc", "mount_exec", "4471")
	assert.False(t, ok, "TTL must be enforced lazily on read, not only by the sweeper")
}

func TestStore_SweepReclaimsExpired(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	past := time.Now().Add(-2 * time.Minute)
	now := time.Now()
	require.NoError(t, s.Set(entry("R1089", "c:abc", "expired", "1", past, time.Minute)))
	require.NoError(t, s.Set(entry("R1089", "c:abc", "live", "1", now, time.Minute)))

	assert.Equal(t, 1, s.Sweep())
	assert.Equal(t, 1, s.Len())
}

func TestStore_ScopeCapRejectsRatherThanEvicting(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{}) // MaxEntriesPerContainer = 4
	now := time.Now()
	for i := 0; i < 4; i++ {
		require.NoError(t, s.Set(entry("R1089", "c:abc", "n", fmt.Sprint(i), now, time.Minute)))
	}

	err := s.Set(entry("R1089", "c:abc", "n", "overflow", now, time.Minute))
	assert.ErrorIs(t, err, ErrScopeCapReached)

	// The critical assertion: nothing already stored was evicted. Evicting would
	// let a hostile container silently disable its own -- or a neighbour's -- rules.
	for i := 0; i < 4; i++ {
		_, ok := s.Get("R1089", armotypes.StateScopeContainer, "c:abc", "n", fmt.Sprint(i))
		assert.True(t, ok, "entry %d was evicted; writes must be rejected instead", i)
	}
}

func TestStore_ScopeCapIsPerScopeNotGlobal(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	now := time.Now()
	for i := 0; i < 4; i++ {
		require.NoError(t, s.Set(entry("R1089", "c:abc", "n", fmt.Sprint(i), now, time.Minute)))
	}
	// A different container is unaffected by its neighbour hitting the cap.
	require.NoError(t, s.Set(entry("R1089", "c:def", "n", "0", now, time.Minute)))
}

// An over-cap scope must still accept an overwrite of a key it already holds:
// refusing would freeze the scope's newest observation out and make a
// bidirectional rule stop updating its own marker.
func TestStore_OverwriteSucceedsEvenAtCap(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	now := time.Now()
	for i := 0; i < 4; i++ {
		require.NoError(t, s.Set(entry("R1089", "c:abc", "n", fmt.Sprint(i), now, time.Minute)))
	}
	later := now.Add(time.Second)
	require.NoError(t, s.Set(entry("R1089", "c:abc", "n", "0", later, time.Minute)),
		"replacing an existing key does not grow the scope, so the cap must not block it")

	got, ok := s.Get("R1089", armotypes.StateScopeContainer, "c:abc", "n", "0")
	require.True(t, ok)
	assert.Equal(t, later, got.Timestamp)
}

func TestStore_OverwriteIsLastWriteWins(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	t1 := time.Now()
	t2 := t1.Add(time.Second)
	require.NoError(t, s.Set(entry("R1089", "c:abc", "n", "1", t1, time.Minute)))
	require.NoError(t, s.Set(entry("R1089", "c:abc", "n", "1", t2, time.Minute)))

	got, ok := s.Get("R1089", armotypes.StateScopeContainer, "c:abc", "n", "1")
	require.True(t, ok)
	assert.Equal(t, t2, got.Timestamp)
	assert.Equal(t, 1, s.Len(), "overwrite must not grow the store")
}

func TestStore_HostBucketHasItsOwnLargerCap(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{}) // host cap 8, container cap 4
	now := time.Now()
	for i := 0; i < 8; i++ {
		require.NoError(t, s.Set(entry("R1089", HostScopeID(), "n", fmt.Sprint(i), now, time.Minute)),
			"host bucket holds the whole node's processes, so it needs a bigger cap than one container")
	}
	assert.ErrorIs(t, s.Set(entry("R1089", HostScopeID(), "n", "8", now, time.Minute)), ErrScopeCapReached)
}

// Node scope is a single node-wide bucket shared by every rule and workload, and
// PurgeScope is only ever called with a container's scope ID, so it is never
// reclaimed on container removal. It therefore needs the same headroom as the
// host bucket -- the per-container cap would starve it on a busy node.
func TestStore_NodeBucketGetsTheLargerCap(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{}) // host/node cap 8, container cap 4
	now := time.Now()
	for i := 0; i < 8; i++ {
		e := entry("R1089", NodeScopeID(), "n", fmt.Sprint(i), now, time.Minute)
		e.Scope = armotypes.StateScopeNode
		require.NoError(t, s.Set(e),
			"node scope must not be bounded by the per-container cap")
	}
	over := entry("R1089", NodeScopeID(), "n", "8", now, time.Minute)
	over.Scope = armotypes.StateScopeNode
	assert.ErrorIs(t, s.Set(over), ErrScopeCapReached)
}

// At the global ceiling with nothing reclaimable, a write that only REPLACES an
// existing key does not grow the store, so it must still be admitted -- otherwise
// a rule loses the ability to refresh a marker exactly when the store is under
// most pressure. Mirrors TestStore_OverwriteSucceedsEvenAtCap for the global cap.
func TestStore_GlobalCapAdmitsAReplacement(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSize = 3
	cfg.MaxEntriesPerContainer = 100
	s := NewStore(cfg, NoopMetrics{})
	now := time.Now()
	for i := 0; i < 3; i++ {
		require.NoError(t, s.Set(entry("R1089", "c:abc", "n", fmt.Sprint(i), now, time.Minute)))
	}

	// A genuine insert is still rejected...
	assert.ErrorIs(t, s.Set(entry("R1089", "c:abc", "n", "new", now, time.Minute)), ErrGlobalCapReached)

	// ...but refreshing an existing key is not.
	later := now.Add(time.Second)
	require.NoError(t, s.Set(entry("R1089", "c:abc", "n", "0", later, time.Minute)),
		"a replacement does not grow the store, so the ceiling must not block it")

	got, ok := s.Get("R1089", armotypes.StateScopeContainer, "c:abc", "n", "0")
	require.True(t, ok)
	assert.Equal(t, later, got.Timestamp)
	assert.Equal(t, 3, s.Len())
}

func TestScopeIDs_HostAndNodeDoNotCollide(t *testing.T) {
	// Host processes carry ContainerID == "", and node scope has no ID. Without
	// type prefixes both would be "" and share a bucket.
	assert.Equal(t, "c:__host__", ContainerScopeID(""))
	assert.Equal(t, "c:abc", ContainerScopeID("abc"))
	assert.Equal(t, "n:", NodeScopeID())
	assert.Equal(t, "p:prod/web-1", PodScopeID("prod", "web-1"))
	assert.NotEqual(t, ContainerScopeID(""), NodeScopeID())
	assert.True(t, IsHostScopeID(ContainerScopeID("")))
	assert.False(t, IsHostScopeID(ContainerScopeID("abc")))
}

func TestStore_PurgeScopeDropsOnlyThatScope(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	now := time.Now()
	require.NoError(t, s.Set(entry("R1089", "c:abc", "n", "1", now, time.Minute)))
	require.NoError(t, s.Set(entry("R1089", "c:def", "n", "1", now, time.Minute)))

	s.PurgeScope("c:abc")
	_, ok := s.Get("R1089", armotypes.StateScopeContainer, "c:abc", "n", "1")
	assert.False(t, ok)
	_, ok = s.Get("R1089", armotypes.StateScopeContainer, "c:def", "n", "1")
	assert.True(t, ok)
	assert.Equal(t, 1, s.Len(), "purge must decrement the global size, not just drop the bucket")
}

func TestStore_DisabledIsANoop(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	s := NewStore(cfg, NoopMetrics{})
	require.NoError(t, s.Set(entry("R1089", "c:abc", "n", "1", time.Now(), time.Minute)))
	_, ok := s.Get("R1089", armotypes.StateScopeContainer, "c:abc", "n", "1")
	assert.False(t, ok, "disabled: writes are no-ops and reads always miss")
	assert.Equal(t, 0, s.Len())
}

// The global ceiling is a backstop. It must reject rather than evict, for the
// same reason the per-scope cap does.
func TestStore_GlobalCapRejectsWhenNothingCanBeReclaimed(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSize = 3
	cfg.MaxEntriesPerContainer = 100
	s := NewStore(cfg, NoopMetrics{})
	now := time.Now()
	for i := 0; i < 3; i++ {
		require.NoError(t, s.Set(entry("R1089", "c:abc", "n", fmt.Sprint(i), now, time.Minute)))
	}

	assert.ErrorIs(t, s.Set(entry("R1089", "c:abc", "n", "3", now, time.Minute)), ErrGlobalCapReached)
	assert.Equal(t, 3, s.Len())
}

// At the ceiling, an expiring entry should make room -- otherwise a node that
// once filled the store would stop correlating forever.
func TestStore_GlobalCapSweepsBeforeRejecting(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSize = 3
	cfg.MaxEntriesPerContainer = 100
	s := NewStore(cfg, NoopMetrics{})
	now := time.Now()
	past := now.Add(-2 * time.Minute)

	require.NoError(t, s.Set(entry("R1089", "c:abc", "n", "0", past, time.Minute)))
	require.NoError(t, s.Set(entry("R1089", "c:abc", "n", "1", now, time.Minute)))
	require.NoError(t, s.Set(entry("R1089", "c:abc", "n", "2", now, time.Minute)))

	require.NoError(t, s.Set(entry("R1089", "c:abc", "n", "3", now, time.Minute)),
		"the expired entry must be reclaimed to admit this write")
	assert.Equal(t, 3, s.Len())
}

func TestStore_ConcurrentSetGetIsRaceFree(t *testing.T) {
	cfg := testConfig()
	cfg.MaxEntriesPerContainer = 10000
	// Both caps have to clear 8*200, or the assertion below is really measuring
	// the global ceiling rejecting writes rather than concurrent correctness.
	cfg.MaxSize = 100000
	s := NewStore(cfg, NoopMetrics{})
	now := time.Now()

	var wg sync.WaitGroup
	for c := 0; c < 8; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			scopeID := fmt.Sprintf("c:%d", c)
			for i := 0; i < 200; i++ {
				_ = s.Set(entry("R1089", scopeID, "n", fmt.Sprint(i), now, time.Minute))
				s.Get("R1089", armotypes.StateScopeContainer, scopeID, "n", fmt.Sprint(i))
			}
		}(c)
	}
	wg.Wait()
	assert.Equal(t, 8*200, s.Len())
}

// Sweep and Set race on the size counter and on bucket maps; a concurrent sweeper
// is exactly what Run does in production.
func TestStore_ConcurrentSweepIsRaceFree(t *testing.T) {
	cfg := testConfig()
	cfg.MaxEntriesPerContainer = 10000
	s := NewStore(cfg, NoopMetrics{})

	stop := make(chan struct{})

	var sweeper sync.WaitGroup
	sweeper.Add(1)
	go func() {
		defer sweeper.Done()
		for {
			select {
			case <-stop:
				return
			default:
				s.Sweep()
			}
		}
	}()

	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		now := time.Now()
		for i := 0; i < 500; i++ {
			// Half of these are born expired, so the sweeper has real work.
			ttl := time.Minute
			if i%2 == 0 {
				ttl = -time.Minute
			}
			_ = s.Set(entry("R1089", "c:abc", "n", fmt.Sprint(i), now, ttl))
		}
	}()

	writer.Wait()
	close(stop)
	sweeper.Wait()
	assert.GreaterOrEqual(t, s.Len(), 0, "size must never go negative")
}
