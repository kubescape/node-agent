package cel

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/rulemanager/statewrites"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A failed compilation is cached as a nil program so the compiler is not
// re-run per event. The typed entry points the state-write executor uses must
// keep reporting that as an error on every call, not only the first: a cached
// failure that evaluates to ("", nil) is accepted as a key, and the executor
// then stores a marker under the EMPTY key -- a scope-wide fact the rule never
// asked for.
func TestEvaluateStringExpressionWithContext_CachedCompileFailureStaysAnError(t *testing.T) {
	c, _, _ := newStateWiringCEL(t)
	ctx := c.CreateEvalContext(execProbeEvent(1))

	for i := 1; i <= 3; i++ {
		s, err := c.EvaluateStringExpressionWithContext(ctx, "not_a_declared_variable")
		assert.Error(t, err, "call %d: a compile failure must not become a successful empty string", i)
		assert.Empty(t, s)
	}
}

func TestEvaluateBoolExpressionWithContext_CachedCompileFailureStaysAnError(t *testing.T) {
	c, _, _ := newStateWiringCEL(t)
	ctx := c.CreateEvalContext(execProbeEvent(1))

	for i := 1; i <= 3; i++ {
		ok, err := c.EvaluateBoolExpressionWithContext(ctx, "not_a_declared_variable")
		assert.Error(t, err, "call %d: a compile failure must keep its guard-error diagnostic", i)
		assert.False(t, ok)
	}
}

// End to end through the executor: the same malformed key on two consecutive
// events must write nothing on either, and both must be counted as key errors.
func TestExecutor_MalformedKeyNeverWritesState(t *testing.T) {
	c, store, cfg := newStateWiringCEL(t)
	metrics := &countingStateMetrics{}
	exec := statewrites.NewExecutor(store, c, metrics)

	compiled, _, err := statewrites.ValidateAll([]armotypes.StateWrite{{
		EventType: armotypes.EventTypeExec,
		Scope:     armotypes.StateScopeContainer,
		Name:      "probe_exec",
		Key:       "not_a_declared_variable",
		TTL:       "10m",
	}}, "R9911", cfg.CelStateStore.MaxTTL)
	require.NoError(t, err)

	for i := 1; i <= 2; i++ {
		ee := execProbeEvent(uint32(i))
		ctx := c.CreateEvalContext(ee)
		exec.Apply(compiled, "R9911", ee, ctx, ResolveEventTime(ee))
		assert.Equal(t, 0, store.Len(), "event %d: a key that cannot compile must not write", i)
	}
	assert.Equal(t, 2, metrics.rejected["key_error"], "both events must be counted as key errors, not just the first")
	_, found := store.Get("R9911", rulestate.ContainerScopeID("abc"), "probe_exec", "")
	assert.False(t, found, "no scope-wide marker may appear under the empty key")
}

type countingStateMetrics struct {
	rulestate.NoopMetrics
	rejected map[string]int
}

func (m *countingStateMetrics) ReportStateWriteRejected(_, reason string) {
	if m.rejected == nil {
		m.rejected = map[string]int{}
	}
	m.rejected[reason]++
}
