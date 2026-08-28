package cel

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/state"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The state library's own tests build a bare cel.NewEnv. Production does not:
// NewCEL installs an xcel TypeAdapter/TypeProvider, every other library, and a
// static optimizer. This test exercises the state functions through THAT env, so
// a wiring problem that only appears in the real evaluator is caught here rather
// than on a cluster.
func newStateWiringCEL(t *testing.T) (*CEL, *rulestate.Store, config.Config) {
	t.Helper()

	cfg := config.Config{}
	cfg.CelStateStore = rulestate.Config{
		Enabled:                true,
		MaxSize:                1000,
		MaxEntriesPerContainer: 100,
		MaxEntriesForHost:      100,
		MaxTTL:                 30 * time.Minute,
		AncestorMaxDepth:       8,
	}

	c, err := NewCEL(objectcache.NewObjectCacheMock(), cfg)
	require.NoError(t, err)

	return c, rulestate.NewStore(cfg.CelStateStore, rulestate.NoopMetrics{}), cfg
}

func execProbeEvent(pid uint32) *events.EnrichedEvent {
	return &events.EnrichedEvent{
		Event: &utils.StructEvent{
			EventType:   utils.ExecveEventType,
			ContainerID: "abc",
			Comm:        "sh",
			Args:        []string{"-c", "# CELSTATE_MARKER\nsleep 8\nexec nc -w 3 h p"},
			Pid:         pid,
		},
		ContainerID: "abc",
		PID:         pid,
	}
}

func networkProbeEvent(pid uint32) *events.EnrichedEvent {
	return &events.EnrichedEvent{
		Event: &utils.StructEvent{
			EventType:   utils.NetworkEventType,
			ContainerID: "abc",
			Comm:        "nc",
			PktType:     "OUTGOING",
			Pid:         pid,
		},
		ContainerID: "abc",
		PID:         pid,
	}
}

func seedState(c *CEL, ctx map[string]any, store *rulestate.Store, ee *events.EnrichedEvent, tracker *state.ReadTracker) {
	ctx[state.AccessorContextKey] = state.NewAccessor(
		store, "R9911",
		map[string]armotypes.StateScope{"probe_exec": armotypes.StateScopeContainer},
		map[armotypes.StateScope]string{
			armotypes.StateScopeContainer: rulestate.ContainerScopeID(ee.ContainerID),
		},
		func() []uint32 { return nil },
		tracker, nil,
	)
}

// The exact predicates the R9911 component-test rule uses.
const (
	probeGuard = `event.comm == 'sh' && event.args.exists(a, a.contains('CELSTATE_MARKER'))`
	probeRead  = `event.pktType == 'OUTGOING' && state.has('probe_exec', string(event.pid))`
)

func TestStateWiring_GuardCompilesAndMatchesInTheRealEnv(t *testing.T) {
	c, _, _ := newStateWiringCEL(t)

	ctx := c.CreateEvalContext(execProbeEvent(4471))
	ok, err := c.EvaluateBoolExpressionWithContext(ctx, probeGuard)
	require.NoError(t, err)
	assert.True(t, ok, "the stateWrites guard must match the marker exec")
}

func TestStateWiring_KeyExpressionEvaluates(t *testing.T) {
	c, _, _ := newStateWiringCEL(t)

	ctx := c.CreateEvalContext(execProbeEvent(4471))
	key, err := c.EvaluateStringExpressionWithContext(ctx, "string(event.pid)")
	require.NoError(t, err)
	assert.Equal(t, "4471", key, "the join key must render as the bare pid")
}

// The end-to-end shape: write on exec, read on network, through the production
// evaluator. This is the unit-level equivalent of the component test.
func TestStateWiring_WriteOnExecThenReadOnNetwork(t *testing.T) {
	c, store, _ := newStateWiringCEL(t)
	tracker := &state.ReadTracker{}

	// --- exec leg: evaluate the guard, then store the entry the executor would.
	execEvent := execProbeEvent(4471)
	execCtx := c.CreateEvalContext(execEvent)
	seedState(c, execCtx, store, execEvent, tracker)

	guardOK, err := c.EvaluateBoolExpressionWithContext(execCtx, probeGuard)
	require.NoError(t, err)
	require.True(t, guardOK, "guard must match, or the write never happens")

	key, err := c.EvaluateStringExpressionWithContext(execCtx, "string(event.pid)")
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, store.Set(&rulestate.Entry{
		RuleID: "R9911", Name: "probe_exec", Key: key,
		Scope:     armotypes.StateScopeContainer,
		ScopeID:   rulestate.ContainerScopeID(execEvent.ContainerID),
		EventType: armotypes.EventTypeExec,
		Timestamp: now, ExpiresAt: now.Add(5 * time.Minute),
		Process: &armotypes.Process{PID: 4471, Comm: "sh"},
		Value:   map[string]any{"probeComm": "sh"},
	}))

	// --- network leg: the predicate must now see it.
	netEvent := networkProbeEvent(4471)
	netCtx := c.CreateEvalContext(netEvent)
	seedState(c, netCtx, store, netEvent, tracker)

	fired, err := c.EvaluateBoolExpressionWithContext(netCtx, probeRead)
	require.NoError(t, err)
	assert.True(t, fired,
		"state written on the exec leg must be readable on the network leg with the same pid")
}

// _pid lands in the returned map as an unsigned value, while event.pid is what
// the event exposes. A rule author's first instinct is to compare them directly,
// so what cel-go actually does with that comparison is worth measuring rather
// than assuming -- if it errors, the rule does not merely miss, it aborts.
func TestStateWiring_ComparingStoredPidAgainstEventPid(t *testing.T) {
	c, store, _ := newStateWiringCEL(t)

	now := time.Now()
	require.NoError(t, store.Set(&rulestate.Entry{
		RuleID: "R9911", Name: "probe_exec", Key: "4471",
		Scope:     armotypes.StateScopeContainer,
		ScopeID:   rulestate.ContainerScopeID("abc"),
		EventType: armotypes.EventTypeExec,
		Timestamp: now, ExpiresAt: now.Add(5 * time.Minute),
		Process: &armotypes.Process{PID: 4471, Comm: "sh"},
	}))

	netEvent := networkProbeEvent(4471)
	ctx := c.CreateEvalContext(netEvent)
	seedState(c, ctx, store, netEvent, nil)

	t.Run("direct numeric comparison", func(t *testing.T) {
		got, err := c.EvaluateBoolExpressionWithContext(ctx,
			`state.get('probe_exec', string(event.pid))._pid == event.pid`)
		if err != nil {
			t.Fatalf("comparing _pid to event.pid ABORTS evaluation: %v\n"+
				"the docs must steer authors away from this form", err)
		}
		assert.True(t, got,
			"the same pid stored and read back must compare equal")
	})

	// The form the docs already recommend for the join, which cannot depend on
	// numeric-type agreement at all.
	t.Run("string comparison", func(t *testing.T) {
		got, err := c.EvaluateBoolExpressionWithContext(ctx,
			`string(state.get('probe_exec', string(event.pid))._pid) == string(event.pid)`)
		require.NoError(t, err)
		assert.True(t, got)
	})

	// A miss returns an empty map, so a read of a key that is not there must
	// degrade rather than abort.
	t.Run("miss degrades", func(t *testing.T) {
		got, err := c.EvaluateBoolExpressionWithContext(ctx,
			`!has(state.get('probe_exec', 'nope')._pid)`)
		require.NoError(t, err, "a miss must not abort evaluation")
		assert.True(t, got)
	})
}
