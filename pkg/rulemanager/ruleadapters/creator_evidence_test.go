package ruleadapters

import (
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetCorrelationEvidence_CarriesCount(t *testing.T) {
	value := map[string]any{"a": "b"}
	counter := &rulestate.Entry{Name: "n", Timestamp: time.Now(), Count: 7, Value: value}
	marker := &rulestate.Entry{Name: "m", Timestamp: time.Now()}

	rf := &types.GenericRuleFailure{}
	setCorrelationEvidence(rf, []*rulestate.Entry{counter, marker})

	ev := rf.GetCorrelationAlert().Correlations
	require.Len(t, ev, 2)
	assert.Equal(t, map[string]any{"a": "b", "_count": int64(7)}, ev[0].Values)
	assert.NotContains(t, value, "_count", "the stored entry's own map is not mutated")
	_, has := ev[1].Values["_count"]
	assert.False(t, has, "a plain marker carries no _count")
}
