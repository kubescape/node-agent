package statewrites

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func base() armotypes.StateWrite {
	return armotypes.StateWrite{
		EventType: armotypes.EventTypeExec,
		Scope:     armotypes.StateScopeContainer,
		Name:      "mount_exec",
		Key:       "string(event.pid)",
		TTL:       "10m",
	}
}

func TestValidate_Accepts(t *testing.T) {
	c, err := Validate(base(), "R1089", 30*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 10*time.Minute, c.TTL)
	assert.Equal(t, "mount_exec", c.Name)
	assert.Equal(t, utils.ExecveEventType, c.EventType,
		"the rule loop compares utils.EventType, so Validate must convert")
}

func TestValidate_ClampsTTLToMax(t *testing.T) {
	w := base()
	w.TTL = "24h"
	c, err := Validate(w, "R1089", 30*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 30*time.Minute, c.TTL, "no rule may pin memory indefinitely")
}

func TestValidate_RejectsUnknownEventType(t *testing.T) {
	w := base()
	w.EventType = armotypes.EventType("nonsense")
	_, err := Validate(w, "R1089", 30*time.Minute)
	require.Error(t, err, "a rule naming a nonexistent event stream must fail loudly at load, not never match at runtime")
}

// EventTypeAll is a rule-binding wildcard, not an event stream. Accepting it
// would yield a rule that loads cleanly and then never matches a concrete event.
func TestValidate_RejectsAllWildcardAsDriver(t *testing.T) {
	w := base()
	w.EventType = armotypes.EventTypeAll
	_, err := Validate(w, "R1089", 30*time.Minute)
	require.Error(t, err, "the binding wildcard cannot drive a state write")
}

func TestValidate_RejectsIdentityScopeInNodeAgent(t *testing.T) {
	w := base()
	w.Scope = armotypes.StateScopeIdentity
	_, err := Validate(w, "R1089", 30*time.Minute)
	require.Error(t, err, "identity scope belongs to the operator")
}

func TestValidate_AcceptsContainerPodAndNodeScopes(t *testing.T) {
	for _, scope := range []armotypes.StateScope{
		armotypes.StateScopeContainer,
		armotypes.StateScopePod,
		armotypes.StateScopeNode,
	} {
		w := base()
		w.Scope = scope
		c, err := Validate(w, "R1089", 30*time.Minute)
		require.NoError(t, err, "scope %q must be accepted", scope)
		assert.Equal(t, scope, c.Scope)
	}
}

func TestValidate_RejectsEmptyScope(t *testing.T) {
	w := base()
	w.Scope = ""
	_, err := Validate(w, "R1089", 30*time.Minute)
	require.Error(t, err)
}

func TestValidate_RejectsReservedValueKeys(t *testing.T) {
	w := base()
	w.Value = map[string]any{"_pid": "event.pid"}
	_, err := Validate(w, "R1089", 30*time.Minute)
	require.Error(t, err, "author values must not shadow engine provenance")
}

func TestValidate_RejectsReservedNamePrefix(t *testing.T) {
	w := base()
	w.Name = "_internal"
	_, err := Validate(w, "R1089", 30*time.Minute)
	require.Error(t, err)
}

func TestValidate_RejectsEmptyNameAndBadTTL(t *testing.T) {
	w := base()
	w.Name = ""
	_, err := Validate(w, "R1089", 30*time.Minute)
	require.Error(t, err)

	w = base()
	w.TTL = "not-a-duration"
	_, err = Validate(w, "R1089", 30*time.Minute)
	require.Error(t, err)
}

func TestValidate_RejectsNonPositiveTTL(t *testing.T) {
	for _, ttl := range []string{"", "0s", "-5m"} {
		w := base()
		w.TTL = ttl
		_, err := Validate(w, "R1089", 30*time.Minute)
		require.Error(t, err, "TTL %q must be rejected: an entry that is born expired is a silently dead rule", ttl)
	}
}

func TestValidate_AllowsEmptyKeyForScopeWideMarker(t *testing.T) {
	w := base()
	w.Key = ""
	c, err := Validate(w, "R1089", 30*time.Minute)
	require.NoError(t, err)
	assert.Empty(t, c.Key)
}

func TestValidate_AcceptsStringValueExpressions(t *testing.T) {
	w := base()
	w.Value = map[string]any{"argv": "event.args"}
	c, err := Validate(w, "R1089", 30*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"argv": "event.args"}, c.Value)
}

// Values are CEL expression strings. A non-string would otherwise be stored as a
// literal, which silently is not what the author asked for.
func TestValidate_RejectsNonStringValueExpressions(t *testing.T) {
	w := base()
	w.Value = map[string]any{"threshold": 5}
	_, err := Validate(w, "R1089", 30*time.Minute)
	require.Error(t, err)
}

func TestValidate_RejectsEmptyValueKey(t *testing.T) {
	w := base()
	w.Value = map[string]any{"": "event.args"}
	_, err := Validate(w, "R1089", 30*time.Minute)
	require.Error(t, err)
}

// Errors must name the rule and the write, or a bad rule in a 50-rule CRD is not
// diagnosable from the log line.
func TestValidate_ErrorNamesRuleAndWrite(t *testing.T) {
	w := base()
	w.TTL = "nope"
	_, err := Validate(w, "R1089", 30*time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "R1089")
	assert.Contains(t, err.Error(), "mount_exec")
}

func TestValidateAll_ReportsFirstFailureAndScopeMap(t *testing.T) {
	good := base()
	other := base()
	other.Name = "egress_seen"
	other.Scope = armotypes.StateScopeNode

	compiled, scopeOf, err := ValidateAll([]armotypes.StateWrite{good, other}, "R1089", 30*time.Minute)
	require.NoError(t, err)
	require.Len(t, compiled, 2)
	assert.Equal(t, map[string]armotypes.StateScope{
		"mount_exec":  armotypes.StateScopeContainer,
		"egress_seen": armotypes.StateScopeNode,
	}, scopeOf, "the scope map is what lets a read resolve its scope from the name alone")

	bad := base()
	bad.Name = ""
	_, _, err = ValidateAll([]armotypes.StateWrite{good, bad}, "R1089", 30*time.Minute)
	require.Error(t, err)
}

// The same name declared twice with different scopes makes a read ambiguous.
func TestValidateAll_RejectsSameNameInTwoScopes(t *testing.T) {
	a := base()
	b := base()
	b.EventType = armotypes.EventTypeNetwork
	b.Scope = armotypes.StateScopeNode

	_, _, err := ValidateAll([]armotypes.StateWrite{a, b}, "R1089", 30*time.Minute)
	require.Error(t, err, "a name must map to exactly one scope, or reads cannot resolve it")
}

// The bidirectional idiom: one name, two event types, same scope. Must be legal.
func TestValidateAll_AllowsSameNameSameScopeAcrossEventTypes(t *testing.T) {
	a := base()
	b := base()
	b.EventType = armotypes.EventTypeNetwork

	compiled, scopeOf, err := ValidateAll([]armotypes.StateWrite{a, b}, "R1089", 30*time.Minute)
	require.NoError(t, err)
	assert.Len(t, compiled, 2)
	assert.Len(t, scopeOf, 1)
}
