package cel

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

func newTestCEL(t *testing.T) *CEL {
	t.Helper()
	c, err := NewCEL(objectcache.NewObjectCacheMock(), config.Config{})
	require.NoError(t, err)
	return c
}

// evalTTY evaluates expr against a single exec event and returns the result.
//
// It asserts compilability first: EvaluateRule reports a compile failure as
// (false, nil), so without this a typo or an unregistered field would look like
// a legitimate false and the test would pass for the wrong reason.
func evalTTY(t *testing.T, e *utils.StructEvent, expr string) bool {
	t.Helper()
	c := newTestCEL(t)
	require.NoError(t, c.registerExpression(expr), "expression must compile")

	ok, err := c.EvaluateRule(&events.EnrichedEvent{Event: e},
		[]typesv1.RuleExpression{{EventType: utils.ExecveEventType, Expression: expr}})
	require.NoError(t, err)
	return ok
}

func TestCELTTYFieldsPhase1(t *testing.T) {
	withTTY := &utils.StructEvent{EventType: utils.ExecveEventType, Comm: "bash", TTY: ptrInt32(3)}
	require.True(t, evalTTY(t, withTTY, `has(event.hasTty) && event.hasTty`))
	require.True(t, evalTTY(t, withTTY, `event.tty == 3`))
	// The device number is not measured on this event.
	require.False(t, evalTTY(t, withTTY, `has(event.ttyMajor)`))

	noTTY := &utils.StructEvent{EventType: utils.ExecveEventType, Comm: "curl", TTY: ptrInt32(0)}
	require.True(t, evalTTY(t, noTTY, `has(event.hasTty) && !event.hasTty`))
}

func TestCELTTYFieldsPhase2(t *testing.T) {
	pts0 := &utils.StructEvent{
		EventType: utils.ExecveEventType,
		Comm:      "bash",
		TTY:       ptrInt32(0),
		TTYMajor:  ptrUint32(136),
		TTYMinor:  ptrUint32(0),
	}
	require.True(t, evalTTY(t, pts0, `has(event.ttyMajor) && event.ttyMajor == 136u`))
	require.True(t, evalTTY(t, pts0, `event.hasTty`), "pts/0 has a terminal")
}

// TestCELForwardCompatibility is the load-bearing test for the whole design: an
// expression written for the future gadget must COMPILE on today's agent and
// evaluate false, rather than fail to compile and silently disable the rule.
func TestCELForwardCompatibility(t *testing.T) {
	expr := `has(event.ttyMajor) && event.ttyMajor == 136u && event.comm == "bash"`

	// The load-bearing assertion: it compiles even though no event carries the field.
	c := newTestCEL(t)
	require.NoError(t, c.registerExpression(expr),
		"a phase-2 expression must compile on a phase-1 agent, or the rule is silently disabled")

	// And it is inert rather than wrong.
	phase1 := &utils.StructEvent{EventType: utils.ExecveEventType, Comm: "bash", TTY: ptrInt32(3)}
	require.False(t, evalTTY(t, phase1, expr))
}

func ptrInt32(v int32) *int32    { return &v }
func ptrUint32(v uint32) *uint32 { return &v }
