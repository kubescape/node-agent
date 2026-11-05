package state

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// incr increments a counter entry in the harness store and declares its name,
// mirroring what the executor's increment phase does.
func (h *harness) incr(name, key string) *rulestate.Entry {
	h.t.Helper()
	e, err := h.store.Incr(&rulestate.Entry{
		RuleID: testRuleID, Name: name, Key: key,
		Scope: armotypes.StateScopeContainer, ScopeID: h.scopeID,
		EventType: armotypes.EventTypeExec,
		Timestamp: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute),
		Process: &armotypes.Process{PID: 4471, Comm: "sh"},
	}, 1)
	require.NoError(h.t, err)
	h.scopeOf[name] = armotypes.StateScopeContainer
	return e
}

func TestAccessor_CountMissIsZero(t *testing.T) {
	h := newHarness(t)
	h.scopeOf["n"] = armotypes.StateScopeContainer
	assert.Equal(t, int64(0), h.accessor().Count("n", "k"))
	assert.Equal(t, int64(0), h.accessor().Count("undeclared", ""))
	assert.Empty(t, h.tracker.Hits(), "a miss is not evidence")
}

func TestAccessor_CountReadsStore(t *testing.T) {
	h := newHarness(t)
	h.incr("n", "k")
	h.incr("n", "k")
	h.incr("n", "k")

	assert.Equal(t, int64(3), h.accessor().Count("n", "k"))
	require.Len(t, h.tracker.Hits(), 1, "a counter read is a hit and becomes evidence")
	assert.Equal(t, int64(3), h.tracker.Hits()[0].Count)
}

func TestAccessor_CountPrefersSnapshot(t *testing.T) {
	h := newHarness(t)
	snap := h.incr("n", "k") // count 1, the value THIS event's increment produced
	a := h.accessor()
	a.RecordIncrement("n", "k", snap)

	// Another event races ahead in the store.
	h.incr("n", "k")
	h.incr("n", "k")

	assert.Equal(t, int64(1), a.Count("n", "k"), "the event reads the count its own increment produced")
	e, ok := a.lookup("n", "k")
	require.True(t, ok)
	assert.Same(t, snap, e, "has/get see the same snapshot as count")
	assert.Equal(t, int64(3), h.accessor().Count("n", "k"), "a fresh accessor reads the store")
}

func TestAccessor_SnapshotIsPerNameAndKey(t *testing.T) {
	h := newHarness(t)
	snap := h.incr("n", "a")
	h.incr("n", "b")
	a := h.accessor()
	a.RecordIncrement("n", "a", snap)
	h.incr("n", "b")

	assert.Equal(t, int64(1), a.Count("n", "a"))
	assert.Equal(t, int64(2), a.Count("n", "b"), "other keys are store reads")
}

func TestAccessor_RecordIncrementIgnoresNil(t *testing.T) {
	h := newHarness(t)
	a := h.accessor()
	a.RecordIncrement("n", "k", nil)
	assert.Equal(t, int64(0), a.Count("n", "k"))
}

func TestAccessor_CountOnNilAccessorIsZero(t *testing.T) {
	var a *Accessor
	assert.Equal(t, int64(0), a.Count("n", "k"))
	a.RecordIncrement("n", "k", &rulestate.Entry{Count: 1})
}

func TestEntryToMap_CountOnlyOnCounters(t *testing.T) {
	marker := entryToMap(&rulestate.Entry{Timestamp: time.Now()})
	_, has := marker["_count"]
	assert.False(t, has, "a plain marker carries no _count")

	counter := entryToMap(&rulestate.Entry{Timestamp: time.Now(), Count: 4})
	assert.Equal(t, int64(4), counter["_count"])
}
