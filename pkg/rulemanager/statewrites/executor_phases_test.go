package statewrites

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingSink captures what the increment phase hands the accessor.
type recordingSink struct {
	entries []*rulestate.Entry
	names   []string
}

func (s *recordingSink) RecordIncrement(name, key string, e *rulestate.Entry) {
	s.entries = append(s.entries, e)
	s.names = append(s.names, name+"/"+key)
}

func incrWrite() armotypes.StateWrite {
	w := base()
	w.Increment = 1
	return w
}

func clearWrite() armotypes.StateWrite {
	w := base()
	w.Clear = true
	return w
}

func TestApplyIncrements_CountsAndRecordsSnapshot(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.strings["string(event.pid)"] = "4471"
	sink := &recordingSink{}
	ex := NewExecutor(store, ev, nil)

	for i := 0; i < 3; i++ {
		ex.ApplyIncrements(mustCompile(t, incrWrite()), "R1089", execEvent("abc"), map[string]any{}, time.Now(), sink)
	}

	got, ok := store.Get("R1089", "c:abc", "mount_exec", "4471")
	require.True(t, ok)
	assert.Equal(t, int64(3), got.Count)
	require.Len(t, sink.entries, 3)
	assert.Equal(t, int64(1), sink.entries[0].Count)
	assert.Equal(t, int64(2), sink.entries[1].Count)
	assert.Equal(t, int64(3), sink.entries[2].Count)
	assert.Equal(t, "mount_exec/4471", sink.names[0])
}

func TestApplyIncrements_GuardFalseSkips(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.bools["is_mount"] = false
	sink := &recordingSink{}
	w := incrWrite()
	w.When = "is_mount"

	NewExecutor(store, ev, nil).ApplyIncrements(mustCompile(t, w), "R1089", execEvent("abc"), map[string]any{}, time.Now(), sink)

	assert.Equal(t, 0, store.Len())
	assert.Empty(t, sink.entries)
}

func TestApplyIncrements_NilSinkStillCounts(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	NewExecutor(store, ev, nil).ApplyIncrements(mustCompile(t, incrWrite()), "R1089", execEvent("abc"), map[string]any{}, time.Now(), nil)
	assert.Equal(t, 1, store.Len())
}

func TestApplyIncrements_SkipsSetAndClearWrites(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	sink := &recordingSink{}
	compiled := append(mustCompile(t, base()), mustCompile(t, clearWrite())...)

	NewExecutor(store, ev, nil).ApplyIncrements(compiled, "R1089", execEvent("abc"), map[string]any{}, time.Now(), sink)

	assert.Equal(t, 0, store.Len(), "a set must not run in the increment phase")
	assert.Empty(t, sink.entries)
}

func TestApply_SkipsIncrementWrites(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()

	NewExecutor(store, ev, nil).Apply(mustCompile(t, incrWrite()), "R1089", execEvent("abc"), map[string]any{}, time.Now())

	assert.Equal(t, 0, store.Len(), "an increment runs before the expression, never in the set/clear phase")
}

func TestApply_ClearDeletes(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.strings["string(event.pid)"] = "4471"
	ex := NewExecutor(store, ev, nil)
	ex.ApplyIncrements(mustCompile(t, incrWrite()), "R1089", execEvent("abc"), map[string]any{}, time.Now(), nil)
	require.Equal(t, 1, store.Len())

	ex.Apply(mustCompile(t, clearWrite()), "R1089", execEvent("abc"), map[string]any{}, time.Now())

	_, ok := store.Get("R1089", "c:abc", "mount_exec", "4471")
	assert.False(t, ok)
	assert.Equal(t, 0, store.Len())
}

func TestApply_ClearGuardFalseKeepsEntry(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.bools["over"] = false
	ex := NewExecutor(store, ev, nil)
	ex.ApplyIncrements(mustCompile(t, incrWrite()), "R1089", execEvent("abc"), map[string]any{}, time.Now(), nil)
	w := clearWrite()
	w.When = "over"

	ex.Apply(mustCompile(t, w), "R1089", execEvent("abc"), map[string]any{}, time.Now())

	assert.Equal(t, 1, store.Len())
}

type countingMetrics struct {
	rulestate.NoopMetrics
	rejected map[string]int
	results  map[string]int
}

func (m *countingMetrics) ReportStateWriteRejected(_, reason string) { m.rejected[reason]++ }
func (m *countingMetrics) ReportStateWrite(_, result string)         { m.results[result]++ }

func TestApply_ClearOnMissingIsSilent(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	m := &countingMetrics{rejected: map[string]int{}, results: map[string]int{}}

	NewExecutor(store, ev, m).Apply(mustCompile(t, clearWrite()), "R1089", execEvent("abc"), map[string]any{}, time.Now())

	assert.Empty(t, m.rejected, "clearing nothing is not a rejection")
	assert.Equal(t, 0, m.results["cleared"])
}

// Review Focus 1: two increment entries for one name and key on one event both
// apply, and the snapshot the expression sees is the last one.
func TestApplyIncrements_TwoWritesSameNameSnapshotIsLast(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.bools["a"] = true
	ev.bools["b"] = true
	sink := &recordingSink{}
	wa := incrWrite()
	wa.When = "a"
	wb := incrWrite()
	wb.When = "b"
	compiled := append(mustCompile(t, wa), mustCompile(t, wb)...)

	NewExecutor(store, ev, nil).ApplyIncrements(compiled, "R1089", execEvent("abc"), map[string]any{}, time.Now(), sink)

	require.Len(t, sink.entries, 2)
	assert.Equal(t, int64(2), sink.entries[len(sink.entries)-1].Count)
}

// The window is measured on the agent's clock, not the event's. Under
// ingestion lag an event's own timestamp can be older than the ttl; anchoring
// the window to it would create an entry that is already expired, so every
// increment would restart at 1 and the counter could never pass 1 during
// exactly the backlog a threshold rule exists for.
func TestApplyIncrements_LaggedEventsStillAccumulate(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ex := NewExecutor(store, ev, nil)
	lagged := time.Now().Add(-20 * time.Minute) // older than the 10m ttl

	for i := 0; i < 3; i++ {
		ex.ApplyIncrements(mustCompile(t, incrWrite()), "R1089", execEvent("abc"), map[string]any{}, lagged, nil)
	}

	got, ok := store.Get("R1089", "c:abc", "mount_exec", "")
	require.True(t, ok)
	assert.Equal(t, int64(3), got.Count)
	assert.Equal(t, lagged, got.Timestamp, "provenance still records when the event happened")
	assert.True(t, got.ExpiresAt.After(time.Now()), "the window runs from when the agent counted it")
}
