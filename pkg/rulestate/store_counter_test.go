package rulestate

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_IncrCreatesWithCountBy(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	now := time.Now()

	got, err := s.Incr(entry("r1", "c:a", "n", "k", now, time.Minute), 1)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int64(1), got.Count)

	e, ok := s.Get("r1", "c:a", "n", "k")
	require.True(t, ok)
	assert.Equal(t, int64(1), e.Count)
	assert.Equal(t, 1, s.Len())
}

func TestStore_IncrAccumulatesAndKeepsWindow(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	first := time.Now()

	e1, err := s.Incr(entry("r1", "c:a", "n", "k", first, time.Minute), 1)
	require.NoError(t, err)
	later := first.Add(30 * time.Second)
	e2, err := s.Incr(entry("r1", "c:a", "n", "k", later, time.Hour), 1)
	require.NoError(t, err)
	e3, err := s.Incr(entry("r1", "c:a", "n", "k", later, time.Hour), 1)
	require.NoError(t, err)

	assert.Equal(t, int64(1), e1.Count)
	assert.Equal(t, int64(2), e2.Count)
	assert.Equal(t, int64(3), e3.Count)
	// The window is fixed from the first increment: a later increment's own
	// timestamp and TTL are ignored.
	assert.Equal(t, first.Add(time.Minute), e3.ExpiresAt)
	assert.Equal(t, first, e3.Timestamp)
	assert.Equal(t, 1, s.Len())
}

func TestStore_IncrIsCopyOnWrite(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	now := time.Now()
	in := entry("r1", "c:a", "n", "k", now, time.Minute)

	p1, err := s.Incr(in, 1)
	require.NoError(t, err)
	p2, err := s.Incr(in, 1)
	require.NoError(t, err)

	assert.NotSame(t, p1, p2)
	assert.Equal(t, int64(1), p1.Count, "a reader holding p1 must not see p2's increment")
	assert.Equal(t, int64(2), p2.Count)
	assert.Equal(t, int64(0), in.Count, "the caller's entry is not mutated")
}

func TestStore_IncrOnExpiredStartsFresh(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	past := time.Now().Add(-10 * time.Minute)
	_, err := s.Incr(entry("r1", "c:a", "n", "k", past, time.Minute), 1)
	require.NoError(t, err)
	_, err = s.Incr(entry("r1", "c:a", "n", "k", past, time.Minute), 1)
	require.NoError(t, err)

	now := time.Now()
	got, err := s.Incr(entry("r1", "c:a", "n", "k", now, time.Minute), 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), got.Count)
	assert.Equal(t, now.Add(time.Minute), got.ExpiresAt)
	assert.Equal(t, 1, s.Len(), "a replacement does not grow the store")
}

func TestStore_IncrRespectsScopeCapOnCreateNotUpdate(t *testing.T) {
	cfg := testConfig()
	s := NewStore(cfg, NoopMetrics{})
	now := time.Now()

	_, err := s.Incr(entry("r1", "c:a", "counter", "", now, time.Minute), 1)
	require.NoError(t, err)
	for i := 1; i < cfg.MaxEntriesPerContainer; i++ {
		require.NoError(t, s.Set(entry("r1", "c:a", "marker", string(rune('a'+i)), now, time.Minute)))
	}
	require.Equal(t, cfg.MaxEntriesPerContainer, s.Len())

	_, err = s.Incr(entry("r1", "c:a", "another", "", now, time.Minute), 1)
	assert.ErrorIs(t, err, ErrScopeCapReached)

	got, err := s.Incr(entry("r1", "c:a", "counter", "", now, time.Minute), 1)
	require.NoError(t, err)
	assert.Equal(t, int64(2), got.Count, "an increment to an existing counter does not grow the scope and must pass at the cap")
}

func TestStore_IncrDisabledIsANoop(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	s := NewStore(cfg, NoopMetrics{})

	got, err := s.Incr(entry("r1", "c:a", "n", "k", time.Now(), time.Minute), 1)
	assert.NoError(t, err)
	assert.Nil(t, got)
	assert.Equal(t, 0, s.Len())
}

func TestStore_ConcurrentIncrSumsExactly(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSize = 100000
	s := NewStore(cfg, NoopMetrics{})
	now := time.Now()

	const workers, perWorker = 64, 100
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				_, err := s.Incr(entry("r1", "c:a", "n", "k", now, time.Minute), 1)
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()

	e, ok := s.Get("r1", "c:a", "n", "k")
	require.True(t, ok)
	assert.Equal(t, int64(workers*perWorker), e.Count)
	assert.Equal(t, 1, s.Len())
}

func TestStore_DeleteRemovesAndShrinks(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	now := time.Now()
	require.NoError(t, s.Set(entry("r1", "c:a", "n", "k", now, time.Minute)))

	assert.True(t, s.Delete("r1", "c:a", "n", "k"))
	_, ok := s.Get("r1", "c:a", "n", "k")
	assert.False(t, ok)
	assert.Equal(t, 0, s.Len())
	assert.False(t, s.Delete("r1", "c:a", "n", "k"), "a second delete finds nothing")
}

func TestStore_DeleteDisabledIsFalse(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	s := NewStore(cfg, NoopMetrics{})
	assert.False(t, s.Delete("r1", "c:a", "n", "k"))
}

func TestStore_SetReplacesACounter(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	now := time.Now()
	_, err := s.Incr(entry("r1", "c:a", "n", "k", now, time.Minute), 1)
	require.NoError(t, err)
	_, err = s.Incr(entry("r1", "c:a", "n", "k", now, time.Minute), 1)
	require.NoError(t, err)

	require.NoError(t, s.Set(entry("r1", "c:a", "n", "k", now, time.Minute)))
	e, ok := s.Get("r1", "c:a", "n", "k")
	require.True(t, ok)
	assert.Equal(t, int64(0), e.Count)
	assert.Equal(t, 1, s.Len())
}
