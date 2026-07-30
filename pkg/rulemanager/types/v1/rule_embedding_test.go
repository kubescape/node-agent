package types

import (
	"encoding/json"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
)

// A representative existing rule (R1004 shape). This must survive embedding
// completely unchanged -- it is the regression gate.
const existingRuleJSON = `{
  "enabled": true,
  "id": "R1004",
  "name": "Process executed from mount",
  "description": "Detecting exec calls from mounted paths.",
  "expressions": {
    "message": "'msg'",
    "uniqueId": "event.comm",
    "ruleExpression": [{"eventType": "exec", "expression": "true"}]
  },
  "profileDependency": 1,
  "profileDataRequired": {"execs": "all"},
  "severity": 5,
  "supportPolicy": false,
  "isTriggerAlert": true,
  "mitreTactic": "TA0002",
  "mitreTechnique": "T1059",
  "tags": ["exec", "mount"]
}`

func TestRule_ExistingFieldsUnchangedAfterEmbedding(t *testing.T) {
	var r Rule
	require.NoError(t, json.Unmarshal([]byte(existingRuleJSON), &r))

	// Promoted from the embedded RuntimeRule.
	assert.True(t, r.Enabled)
	assert.Equal(t, "R1004", r.ID)
	assert.Equal(t, "Process executed from mount", r.Name)
	assert.Equal(t, 5, r.Severity)
	assert.Equal(t, armotypes.ProfileDependency(1), r.ProfileDependency)
	assert.Equal(t, []string{"exec", "mount"}, r.Tags)
	assert.True(t, r.IsTriggerAlert)
	assert.Equal(t, "TA0002", r.MitreTactic)

	// Shadowed: still node-agent's own type, still utils.EventType.
	require.Len(t, r.Expressions.RuleExpression, 1)
	assert.Equal(t, utils.ExecveEventType, r.Expressions.RuleExpression[0].EventType)
	assert.Equal(t, "event.comm", r.Expressions.UniqueID)

	// Shadowed: node-agent's FieldRequirement semantics, including Declared.
	require.NotNil(t, r.ProfileDataRequired)
	assert.True(t, r.ProfileDataRequired.Execs.All)
	assert.True(t, r.ProfileDataRequired.Execs.Declared)
	assert.False(t, r.ProfileDataRequired.Opens.Declared,
		"an absent surface must stay undeclared -- this is the semantics armotypes lacks")
}

func TestRule_StateWritesAreReadableViaEmbedding(t *testing.T) {
	const withState = `{
      "id": "R1089",
      "stateWrites": [{
        "eventType": "exec",
        "when": "true",
        "scope": "container",
        "name": "mount_exec",
        "key": "string(event.pid)",
        "ttl": "10m"
      }],
      "expressions": {"message": "'m'", "uniqueId": "'u'", "ruleExpression": []}
    }`

	var r Rule
	require.NoError(t, json.Unmarshal([]byte(withState), &r))

	require.Len(t, r.StateWrites, 1)
	w := r.StateWrites[0]
	assert.Equal(t, armotypes.EventTypeExec, w.EventType)
	assert.Equal(t, armotypes.StateScopeContainer, w.Scope)
	assert.Equal(t, "mount_exec", w.Name)
	assert.Equal(t, "10m", w.TTL)
}

func TestRule_PrefilterStillExcludedFromSerialization(t *testing.T) {
	data, err := json.Marshal(Rule{})
	require.NoError(t, err)
	assert.NotContains(t, string(data), "Prefilter")
	assert.NotContains(t, string(data), "prefilter")
}

func TestRule_ShadowedFieldWinsOverEmbedded(t *testing.T) {
	// Proves the depth rule for encoding/json: the outer Expressions is
	// populated, and the embedded RuntimeRule.Expressions is left at its zero
	// value. If this ever inverts, EventType silently becomes
	// armotypes.EventType and the rule loop stops matching.
	var r Rule
	require.NoError(t, json.Unmarshal([]byte(existingRuleJSON), &r))
	assert.Len(t, r.Expressions.RuleExpression, 1)
	assert.Empty(t, r.RuntimeRule.Expressions.RuleExpression,
		"embedded Expressions must stay unused; the shadow is deliberate")
}

// unstructuredRule is the production decoding path: rules arrive from the CRD as
// unstructured maps and are converted by apimachinery, NOT by encoding/json.
// Unlike encoding/json, apimachinery has no depth-based conflict resolution --
// it visits every field of the outer struct independently -- so the two decoders
// genuinely disagree about the shadowed fields. What must hold on BOTH paths is
// that the depth-0 shadow (the one all node-agent code reads) is correct.
func unstructuredRule(t *testing.T, raw string) Rule {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &m))

	var r Rule
	require.NoError(t, k8sruntime.DefaultUnstructuredConverter.FromUnstructured(m, &r))
	return r
}

func TestRule_DecodesViaApimachineryLikeTheCRDPath(t *testing.T) {
	r := unstructuredRule(t, existingRuleJSON)

	assert.True(t, r.Enabled)
	assert.Equal(t, "R1004", r.ID)
	assert.Equal(t, 5, r.Severity)
	assert.Equal(t, armotypes.ProfileDependency(1), r.ProfileDependency)
	assert.Equal(t, []string{"exec", "mount"}, r.Tags)
	assert.Equal(t, "TA0002", r.MitreTactic)

	// The field the rule loop actually compares against.
	require.Len(t, r.Expressions.RuleExpression, 1)
	assert.Equal(t, utils.ExecveEventType, r.Expressions.RuleExpression[0].EventType)
	assert.Equal(t, "event.comm", r.Expressions.UniqueID)

	require.NotNil(t, r.ProfileDataRequired)
	assert.True(t, r.ProfileDataRequired.Execs.All)
	assert.True(t, r.ProfileDataRequired.Execs.Declared)
	assert.False(t, r.ProfileDataRequired.Opens.Declared)
}

func TestRule_StateWritesDecodeViaApimachinery(t *testing.T) {
	const withState = `{
      "id": "R1089",
      "stateWrites": [{
        "eventType": "exec",
        "scope": "container",
        "name": "mount_exec",
        "key": "string(event.pid)",
        "value": {"argv": "event.args"},
        "ttl": "10m"
      }],
      "expressions": {"message": "'m'", "uniqueId": "'u'", "ruleExpression": []}
    }`

	r := unstructuredRule(t, withState)

	require.Len(t, r.StateWrites, 1)
	w := r.StateWrites[0]
	assert.Equal(t, armotypes.EventTypeExec, w.EventType)
	assert.Equal(t, armotypes.StateScopeContainer, w.Scope)
	assert.Equal(t, "mount_exec", w.Name)
	assert.Equal(t, "string(event.pid)", w.Key)
	assert.Equal(t, "10m", w.TTL)
	assert.Equal(t, map[string]any{"argv": "event.args"}, w.Value)
}
