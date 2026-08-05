package statewrites

import (
	"errors"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeEvaluator returns canned results per expression, so the executor's own
// logic is under test rather than CEL's.
type fakeEvaluator struct {
	bools   map[string]bool
	strings map[string]string
	boolErr map[string]bool
	strErr  map[string]bool
}

func newFakeEvaluator() *fakeEvaluator {
	return &fakeEvaluator{
		bools:   map[string]bool{},
		strings: map[string]string{},
		boolErr: map[string]bool{},
		strErr:  map[string]bool{},
	}
}

func (f *fakeEvaluator) EvaluateBoolExpressionWithContext(_ map[string]any, expr string) (bool, error) {
	if f.boolErr[expr] {
		return false, errors.New("boom")
	}
	return f.bools[expr], nil
}

func (f *fakeEvaluator) EvaluateStringExpressionWithContext(_ map[string]any, expr string) (string, error) {
	if f.strErr[expr] {
		return "", errors.New("boom")
	}
	return f.strings[expr], nil
}

func testStore(t *testing.T) *rulestate.Store {
	t.Helper()
	return rulestate.NewStore(rulestate.Config{
		Enabled:                true,
		MaxSize:                1000,
		MaxEntriesPerContainer: 100,
		MaxEntriesForHost:      100,
		MaxTTL:                 30 * time.Minute,
	}, rulestate.NoopMetrics{})
}

func execEvent(containerID string) *events.EnrichedEvent {
	return &events.EnrichedEvent{
		Event: &utils.StructEvent{
			EventType:   utils.ExecveEventType,
			ContainerID: containerID,
			Comm:        "xmrig",
			Pcomm:       "sh",
			ExePath:     "/mnt/data/xmrig",
			Cwd:         "/mnt/data",
			Namespace:   "prod",
			Pod:         "web-1",
			Pid:         4471,
			Ppid:        900,
		},
		ContainerID: containerID,
		PID:         4471,
		PPID:        900,
	}
}

func mustCompile(t *testing.T, w armotypes.StateWrite) []Compiled {
	t.Helper()
	c, err := Validate(w, "R1089", 30*time.Minute)
	require.NoError(t, err)
	return []Compiled{c}
}

func TestApply_GuardTrueStoresEntry(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.bools["is_mount"] = true
	ev.strings["string(event.pid)"] = "4471"

	w := base()
	w.When = "is_mount"
	eventTime := time.Now()

	NewExecutor(store, ev, nil).Apply(mustCompile(t, w), "R1089", execEvent("abc"),
		map[string]any{}, eventTime)

	got, ok := store.Get("R1089", armotypes.StateScopeContainer, "c:abc", "mount_exec", "4471")
	require.True(t, ok)
	assert.Equal(t, eventTime, got.Timestamp,
		"the entry must carry the event time, so _ts guards compare the same clock the predicate saw")
	assert.Equal(t, eventTime.Add(10*time.Minute), got.ExpiresAt)
	require.NotNil(t, got.Process)
	assert.Equal(t, uint32(4471), got.Process.PID)
	assert.Equal(t, "xmrig", got.Process.Comm)
	assert.Equal(t, "/mnt/data/xmrig", got.Process.Path)
	assert.Equal(t, armotypes.EventTypeExec, got.EventType)
}

func TestApply_GuardFalseStoresNothing(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.bools["is_mount"] = false

	w := base()
	w.When = "is_mount"

	NewExecutor(store, ev, nil).Apply(mustCompile(t, w), "R1089", execEvent("abc"),
		map[string]any{}, time.Now())

	assert.Equal(t, 0, store.Len())
}

func TestApply_AbsentGuardAlwaysStores(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.strings["string(event.pid)"] = "4471"

	w := base() // When == ""
	NewExecutor(store, ev, nil).Apply(mustCompile(t, w), "R1089", execEvent("abc"),
		map[string]any{}, time.Now())

	_, ok := store.Get("R1089", armotypes.StateScopeContainer, "c:abc", "mount_exec", "4471")
	assert.True(t, ok)
}

// Host processes carry no container ID and must land in the explicit host bucket,
// not under the empty string.
func TestApply_HostProcessUsesHostScopeID(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.strings["string(event.pid)"] = "4471"

	NewExecutor(store, ev, nil).Apply(mustCompile(t, base()), "R1089", execEvent(""),
		map[string]any{}, time.Now())

	_, ok := store.Get("R1089", armotypes.StateScopeContainer, rulestate.HostScopeID(), "mount_exec", "4471")
	assert.True(t, ok, "a host process must be addressable under %q", rulestate.HostScopeID())
}

// Write-without-alerting: the write leg's event type need not appear in any
// ruleExpression. The executor sees only compiled writes, so this must hold.
func TestApply_StoresForEventTypeWithNoRuleExpression(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.strings["string(event.pid)"] = "4471"

	// No ruleExpression exists anywhere for this rule; only the write clause.
	NewExecutor(store, ev, nil).Apply(mustCompile(t, base()), "R1089", execEvent("abc"),
		map[string]any{}, time.Now())

	assert.Equal(t, 1, store.Len())
}

func TestApply_SkipsWritesForOtherEventTypes(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()

	w := base()
	w.EventType = armotypes.EventTypeNetwork // event is exec

	NewExecutor(store, ev, nil).Apply(mustCompile(t, w), "R1089", execEvent("abc"),
		map[string]any{}, time.Now())

	assert.Equal(t, 0, store.Len())
}

func TestApply_ValueExpressionsAreStored(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.strings["string(event.pid)"] = "4471"
	ev.strings["event.args"] = "-o pool:4444"

	w := base()
	w.Value = map[string]any{"argv": "event.args"}

	NewExecutor(store, ev, nil).Apply(mustCompile(t, w), "R1089", execEvent("abc"),
		map[string]any{}, time.Now())

	got, ok := store.Get("R1089", armotypes.StateScopeContainer, "c:abc", "mount_exec", "4471")
	require.True(t, ok)
	assert.Equal(t, map[string]any{"argv": "-o pool:4444"}, got.Value)
}

func TestApply_EmptyKeyYieldsOneScopeWideEntry(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()

	w := base()
	w.Key = ""

	NewExecutor(store, ev, nil).Apply(mustCompile(t, w), "R1089", execEvent("abc"),
		map[string]any{}, time.Now())

	_, ok := store.Get("R1089", armotypes.StateScopeContainer, "c:abc", "mount_exec", "")
	assert.True(t, ok)
	assert.Equal(t, 1, store.Len())
}

// A broken guard must not store; a broken key must not store under a wrong key.
func TestApply_ExpressionErrorsSkipTheWrite(t *testing.T) {
	t.Run("guard error", func(t *testing.T) {
		store := testStore(t)
		ev := newFakeEvaluator()
		ev.boolErr["bad"] = true
		w := base()
		w.When = "bad"
		NewExecutor(store, ev, nil).Apply(mustCompile(t, w), "R1089", execEvent("abc"),
			map[string]any{}, time.Now())
		assert.Equal(t, 0, store.Len())
	})

	t.Run("key error", func(t *testing.T) {
		store := testStore(t)
		ev := newFakeEvaluator()
		ev.strErr["string(event.pid)"] = true
		NewExecutor(store, ev, nil).Apply(mustCompile(t, base()), "R1089", execEvent("abc"),
			map[string]any{}, time.Now())
		assert.Equal(t, 0, store.Len())
	})
}

// Pod scope on an event with no pod identity has nothing to resolve against; the
// write is dropped rather than landing in a bogus bucket.
func TestApply_PodScopeWithoutPodIdentityIsDropped(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.strings["string(event.pid)"] = "4471"

	w := base()
	w.Scope = armotypes.StateScopePod

	enriched := execEvent("abc")
	enriched.Event.(*utils.StructEvent).Pod = ""

	NewExecutor(store, ev, nil).Apply(mustCompile(t, w), "R1089", enriched,
		map[string]any{}, time.Now())

	assert.Equal(t, 0, store.Len())
}

func TestApply_PodScopeUsesNamespacedID(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.strings["string(event.pid)"] = "4471"

	w := base()
	w.Scope = armotypes.StateScopePod

	NewExecutor(store, ev, nil).Apply(mustCompile(t, w), "R1089", execEvent("abc"),
		map[string]any{}, time.Now())

	_, ok := store.Get("R1089", armotypes.StateScopePod, rulestate.PodScopeID("prod", "web-1"),
		"mount_exec", "4471")
	assert.True(t, ok)
}

// A guard that itself reads state is how multi-step chains are built; the
// executor must not treat a state-reading guard specially.
func TestApply_GuardMayItselfDependOnState(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	ev.bools[`state.has("step1")`] = true
	ev.strings["string(event.pid)"] = "4471"

	w := base()
	w.Name = "step2"
	w.When = `state.has("step1")`

	NewExecutor(store, ev, nil).Apply(mustCompile(t, w), "R1089", execEvent("abc"),
		map[string]any{}, time.Now())

	_, ok := store.Get("R1089", armotypes.StateScopeContainer, "c:abc", "step2", "4471")
	assert.True(t, ok)
}

func TestApply_NilSafeOnMissingPieces(t *testing.T) {
	store := testStore(t)
	ev := newFakeEvaluator()
	e := NewExecutor(store, ev, nil)

	// No writes, and a nil eval context: both must be no-ops, not panics.
	e.Apply(nil, "R1089", execEvent("abc"), map[string]any{}, time.Now())
	e.Apply(mustCompile(t, base()), "R1089", execEvent("abc"), nil, time.Now())
	assert.Equal(t, 0, store.Len())
}

func TestScopeIDs_ResolvesFromTheEventOnly(t *testing.T) {
	ids := ScopeIDs(execEvent("abc"))
	assert.Equal(t, "c:abc", ids[armotypes.StateScopeContainer])
	assert.Equal(t, rulestate.NodeScopeID(), ids[armotypes.StateScopeNode])
	assert.Equal(t, "p:prod/web-1", ids[armotypes.StateScopePod])

	// Host: container scope resolves to the host bucket, pod scope is absent.
	hostIDs := ScopeIDs(&events.EnrichedEvent{
		Event:       &utils.StructEvent{EventType: utils.ExecveEventType},
		ContainerID: "",
	})
	assert.Equal(t, rulestate.HostScopeID(), hostIDs[armotypes.StateScopeContainer])
	_, hasPod := hostIDs[armotypes.StateScopePod]
	assert.False(t, hasPod)
}
