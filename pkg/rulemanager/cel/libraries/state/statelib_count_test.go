package state

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/google/cel-go/checker"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (h *harness) evalInt(expr string) int64 {
	h.t.Helper()
	v, ok := h.eval(expr).(int64)
	require.True(h.t, ok, "expression must yield an int: %s", expr)
	return v
}

func TestStateCount_MissIsZeroNotError(t *testing.T) {
	h := newHarness(t)
	assert.Equal(t, int64(0), h.evalInt(`state.count("nope")`))
	assert.Equal(t, int64(0), h.evalInt(`state.count("nope", "k")`))
	assert.True(t, h.evalBool(`state.count("nope", "k") == 0`))
}

func TestStateCount_ReadsStore(t *testing.T) {
	h := newHarness(t)
	h.incr("n", "k")
	h.incr("n", "k")
	h.incr("wide", "")

	assert.Equal(t, int64(2), h.evalInt(`state.count("n", "k")`))
	assert.Equal(t, int64(1), h.evalInt(`state.count("wide")`))
	assert.True(t, h.evalBool(`state.count("n", "k") >= 2`))
}

func TestStateCount_ReadsSnapshot(t *testing.T) {
	h := newHarness(t)
	snap := h.incr("n", "k")
	h.incr("n", "k")

	ast, iss := h.env.Compile(`state.count("n", "k")`)
	require.NoError(t, iss.Err())
	prg, err := h.env.Program(ast)
	require.NoError(t, err)
	a := h.accessor()
	a.RecordIncrement("n", "k", snap)
	out, _, err := prg.Eval(map[string]any{AccessorContextKey: a, "timestamp": h.now})
	require.NoError(t, err)
	assert.Equal(t, int64(1), out.Value())
}

func TestStateGet_ExposesCount(t *testing.T) {
	h := newHarness(t)
	h.incr("n", "k")
	h.incr("n", "k")
	h.write(testRuleID, "c:abc", "marker", "k", h.now)

	assert.Equal(t, int64(2), h.evalInt(`state.get("n", "k")._count`))
	assert.True(t, h.evalBool(`has(state.get("n", "k")._count)`))
	assert.False(t, h.evalBool(`has(state.get("marker", "k")._count)`), "_count only on counters")
	assert.Equal(t, "2", h.evalString(`string(state.count("n", "k"))`))
}

func TestStateCount_DisabledStoreIsZero(t *testing.T) {
	h := newHarness(t)
	disabled := rulestate.Config{Enabled: false}
	h.store = rulestate.NewStore(disabled, rulestate.NoopMetrics{})
	h.scopeOf["n"] = armotypes.StateScopeContainer
	assert.Equal(t, int64(0), h.evalInt(`state.count("n", "k")`))

	h.store = nil
	assert.Equal(t, int64(0), h.evalInt(`state.count("n", "k")`), "no store at all is a miss, not a panic")
}

func TestStateCount_CostEstimate(t *testing.T) {
	est := &stateCostEstimator{cfg: config.Config{}}
	for _, id := range []string{"state_count_name", "state_count_name_key"} {
		c := est.EstimateCallCost("count", id, nil, nil)
		require.NotNil(t, c, id)
		assert.Equal(t, checker.CostEstimate{Min: 10, Max: 10}, c.CostEstimate, id)
	}
}
