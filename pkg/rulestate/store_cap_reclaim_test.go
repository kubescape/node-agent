package rulestate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A full bucket whose entries have expired must not keep rejecting new writes
// until the periodic sweep runs: expired slots are reclaimed on the cap-hit
// path, so one rule's dead markers cannot hold a container's cap against
// another rule's live writes.
func TestStore_ScopeCapReclaimsExpiredBeforeRejectingSet(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	past := time.Now().Add(-time.Minute)
	for i := 0; i < testConfig().MaxEntriesPerContainer; i++ {
		require.NoError(t, s.Set(entry("R-noisy", "c:abc", "seen_path", string(rune('a'+i)), past, time.Second)))
	}
	// Every slot is held by an expired entry.
	err := s.Set(entry("R-port", "c:abc", "ports", "1", time.Now(), time.Minute))
	require.NoError(t, err, "expired entries must be reclaimed before the cap rejects a live write")
	got, ok := s.Get("R-port", "c:abc", "ports", "1")
	require.True(t, ok)
	assert.Equal(t, "R-port", got.RuleID)
	assert.Equal(t, 1, s.Len(), "the expired entries were freed, only the live one remains")
}

func TestStore_ScopeCapReclaimsExpiredBeforeRejectingIncr(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	past := time.Now().Add(-time.Minute)
	for i := 0; i < testConfig().MaxEntriesPerContainer; i++ {
		require.NoError(t, s.Set(entry("R-noisy", "c:abc", "seen_path", string(rune('a'+i)), past, time.Second)))
	}
	stored, err := s.Incr(entry("R-port", "c:abc", "ports", "1", time.Now(), time.Minute), 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), stored.Count)
	assert.Equal(t, 1, s.Len())
}

// Live entries are never evicted to make room: the cap still rejects when the
// bucket is genuinely full.
func TestStore_ScopeCapStillRejectsWhenNothingExpired(t *testing.T) {
	s := NewStore(testConfig(), NoopMetrics{})
	now := time.Now()
	for i := 0; i < testConfig().MaxEntriesPerContainer; i++ {
		require.NoError(t, s.Set(entry("R-noisy", "c:abc", "seen_path", string(rune('a'+i)), now, time.Minute)))
	}
	require.ErrorIs(t, s.Set(entry("R-port", "c:abc", "ports", "1", now, time.Minute)), ErrScopeCapReached)
	_, err := s.Incr(entry("R-port", "c:abc", "ports", "1", now, time.Minute), 1)
	require.ErrorIs(t, err, ErrScopeCapReached)
}
