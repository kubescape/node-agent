package ruleadapters

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func execHit() *rulestate.Entry {
	return &rulestate.Entry{
		RuleID:    "R1089",
		Name:      "mount_exec",
		Scope:     armotypes.StateScopeContainer,
		ScopeID:   "c:abc",
		Key:       "4471",
		EventType: armotypes.EventTypeExec,
		Timestamp: time.Date(2026, 7, 28, 12, 0, 3, 0, time.UTC),
		Process: &armotypes.Process{
			PID: 4471, Comm: "xmrig", Path: "/mnt/data/xmrig",
		},
		Value: map[string]any{"argv": "-o pool:4444"},
	}
}

func TestCorrelationEvidence_OneHitBecomesOneEvidenceEntry(t *testing.T) {
	failure := &types.GenericRuleFailure{}
	setCorrelationEvidence(failure, []*rulestate.Entry{execHit()})

	got := failure.GetCorrelationAlert()
	require.Len(t, got.Correlations, 1)

	c := got.Correlations[0]
	assert.Equal(t, "mount_exec", c.Name)
	assert.Equal(t, armotypes.EventTypeExec, c.EventType)
	assert.Equal(t, time.Date(2026, 7, 28, 12, 0, 3, 0, time.UTC), c.Timestamp)
	assert.Equal(t, armotypes.StateScopeContainer, c.Scope)
	assert.Equal(t, "4471", c.Key)
	require.NotNil(t, c.Process)
	assert.Equal(t, uint32(4471), c.Process.PID)
	assert.Equal(t, "/mnt/data/xmrig", c.Process.Path)
	assert.Equal(t, map[string]any{"argv": "-o pool:4444"}, c.Values)
	assert.Nil(t, c.Admission, "node-agent entries carry a Process, never an Admission")
}

func TestCorrelationEvidence_MultipleHitsArePreservedInOrder(t *testing.T) {
	second := execHit()
	second.Name = "egress_seen"

	failure := &types.GenericRuleFailure{}
	setCorrelationEvidence(failure, []*rulestate.Entry{execHit(), second})

	got := failure.GetCorrelationAlert()
	require.Len(t, got.Correlations, 2)
	assert.Equal(t, "mount_exec", got.Correlations[0].Name)
	assert.Equal(t, "egress_seen", got.Correlations[1].Name)
}

func TestCorrelationEvidence_NoHitsLeavesTheAlertUntouched(t *testing.T) {
	failure := &types.GenericRuleFailure{}
	setCorrelationEvidence(failure, nil)
	assert.Empty(t, failure.GetCorrelationAlert().Correlations)

	// omitempty means an uncorrelated alert must not gain a "correlations" key --
	// every existing alert on the wire has to stay byte-identical.
	data, err := json.Marshal(failure.GetCorrelationAlert())
	require.NoError(t, err)
	assert.NotContains(t, string(data), "correlations")
}

func TestCorrelationEvidence_NilEntriesAreSkipped(t *testing.T) {
	failure := &types.GenericRuleFailure{}
	setCorrelationEvidence(failure, []*rulestate.Entry{nil, execHit(), nil})
	assert.Len(t, failure.GetCorrelationAlert().Correlations, 1)
}

func TestCorrelationEvidence_AllNilEntriesAddsNothing(t *testing.T) {
	failure := &types.GenericRuleFailure{}
	setCorrelationEvidence(failure, []*rulestate.Entry{nil, nil})
	assert.Empty(t, failure.GetCorrelationAlert().Correlations)
}

// Correlation must ENRICH an incident, never re-key it. If InfectedPID or
// RuntimeProcessDetails shifted to the remembered process, backend incident
// grouping would move the alert to a different incident.
func TestCorrelationEvidence_DoesNotRekeyTheAlert(t *testing.T) {
	failure := &types.GenericRuleFailure{
		BaseRuntimeAlert: armotypes.BaseRuntimeAlert{
			InfectedPID: 9999, // the TRIGGERING process
		},
		RuntimeProcessDetails: armotypes.ProcessTree{
			ContainerID: "triggering-container",
			ProcessTree: armotypes.Process{PID: 9999},
		},
	}

	setCorrelationEvidence(failure, []*rulestate.Entry{execHit()}) // remembered PID 4471

	assert.Equal(t, uint32(9999), failure.GetBaseRuntimeAlert().InfectedPID,
		"InfectedPID must still describe the triggering event")
	assert.Equal(t, uint32(9999), failure.GetRuntimeProcessDetails().ProcessTree.PID)
	assert.Equal(t, "triggering-container", failure.GetRuntimeProcessDetails().ContainerID)
}

// The evidence must survive onto the wire alert, not just the internal failure.
func TestCorrelationEvidence_SerializesUnderCorrelations(t *testing.T) {
	failure := &types.GenericRuleFailure{}
	setCorrelationEvidence(failure, []*rulestate.Entry{execHit()})

	alert := armotypes.RuntimeAlert{
		CorrelationAlert: failure.GetCorrelationAlert(),
	}
	data, err := json.Marshal(alert)
	require.NoError(t, err)

	var round map[string]any
	require.NoError(t, json.Unmarshal(data, &round))

	raw, ok := round["correlations"]
	require.True(t, ok, "CorrelationAlert is inlined, so evidence appears at the alert top level")
	entries, ok := raw.([]any)
	require.True(t, ok)
	require.Len(t, entries, 1)
	assert.Equal(t, "mount_exec", entries[0].(map[string]any)["name"])
}
