package cel

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
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
	return evalTTYEvent(t, e, e.EventType, expr)
}

// evalTTYEvent is the generalised form of evalTTY: it accepts any utils.K8sEvent
// implementer (StructEvent or DatasourceEvent) so the same CEL expressions can
// be exercised against both the test-only presence path and the production
// DatasourceEvent.FieldPresent path.
//
// It keeps the same load-bearing discipline as evalTTY: it asserts
// c.registerExpression(expr) succeeds BEFORE evaluating, because EvaluateRule
// reports a compile failure as (false, nil) — without the compile assertion a
// typo or type error looks exactly like a legitimate false.
func evalTTYEvent(t *testing.T, e utils.K8sEvent, eventType utils.EventType, expr string) bool {
	t.Helper()
	c := newTestCEL(t)
	require.NoError(t, c.registerExpression(expr), "expression must compile")

	ok, err := c.EvaluateRule(&events.EnrichedEvent{Event: e},
		[]typesv1.RuleExpression{{EventType: eventType, Expression: expr}})
	require.NoError(t, err)
	return ok
}

// newDatasourceExecEvent builds a synthetic "exec" datasource containing only
// the tty-related fields listed in fields, plus a filler "comm" field so the
// datasource is not degenerate. It mirrors the newExecEvent helper in
// pkg/utils/datasource_event_tty_test.go, which lives in package utils and is
// not importable from package cel.
type ttyDSFields struct {
	tty      *int32
	ttyMajor *uint32
	ttyMinor *uint32
}

func newDatasourceExecEvent(t *testing.T, eventType utils.EventType, f ttyDSFields) *utils.DatasourceEvent {
	t.Helper()

	ds, err := datasource.New(datasource.TypeSingle, "exec")
	require.NoError(t, err)

	commAcc, err := ds.AddField("comm", api.Kind_String)
	require.NoError(t, err)

	var ttyAcc, majorAcc, minorAcc datasource.FieldAccessor
	if f.tty != nil {
		ttyAcc, err = ds.AddField("tty", api.Kind_Int32)
		require.NoError(t, err)
	}
	if f.ttyMajor != nil {
		majorAcc, err = ds.AddField("tty_major", api.Kind_Uint32)
		require.NoError(t, err)
	}
	if f.ttyMinor != nil {
		minorAcc, err = ds.AddField("tty_minor", api.Kind_Uint32)
		require.NoError(t, err)
	}

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	t.Cleanup(func() { ds.Release(data) })

	require.NoError(t, commAcc.PutString(data, "bash"))
	if f.tty != nil {
		require.NoError(t, ttyAcc.PutInt32(data, *f.tty))
	}
	if f.ttyMajor != nil {
		require.NoError(t, majorAcc.PutUint32(data, *f.ttyMajor))
	}
	if f.ttyMinor != nil {
		require.NoError(t, minorAcc.PutUint32(data, *f.ttyMinor))
	}

	return &utils.DatasourceEvent{
		Data:       data,
		Datasource: ds,
		EventType:  eventType,
	}
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

// --- DatasourceEvent coverage -----------------------------------------------
//
// The tests above all build *utils.StructEvent, so presenceOf() is only ever
// exercised against StructEvent.FieldPresent's simple switch — never against
// DatasourceEvent.FieldPresent, which is what runs in production. The tests
// below evaluate the same CEL expressions against a *utils.DatasourceEvent
// built over a synthetic datasource, so a regression in the datasource
// presence path would be caught here.

// TestCELTTYFieldsPhase1_DatasourceEvent mirrors TestCELTTYFieldsPhase1 but
// against a DatasourceEvent backed by a datasource that only emits "tty".
func TestCELTTYFieldsPhase1_DatasourceEvent(t *testing.T) {
	withTTY := newDatasourceExecEvent(t, utils.ExecveEventType, ttyDSFields{tty: ptrInt32(3)})
	require.True(t, evalTTYEvent(t, withTTY, utils.ExecveEventType, `has(event.hasTty) && event.hasTty`))
	require.True(t, evalTTYEvent(t, withTTY, utils.ExecveEventType, `event.tty == 3`))
	// The device number is not measured by this datasource shape.
	require.False(t, evalTTYEvent(t, withTTY, utils.ExecveEventType, `has(event.ttyMajor)`))
}

// TestCELTTYFieldsPhase2_DatasourceEvent mirrors TestCELTTYFieldsPhase2 but
// against a DatasourceEvent backed by a datasource that emits tty, tty_major,
// and tty_minor — the pts/0 shape (index 0, major 136, minor 0).
func TestCELTTYFieldsPhase2_DatasourceEvent(t *testing.T) {
	pts0 := newDatasourceExecEvent(t, utils.ExecveEventType, ttyDSFields{
		tty:      ptrInt32(0),
		ttyMajor: ptrUint32(136),
		ttyMinor: ptrUint32(0),
	})
	require.True(t, evalTTYEvent(t, pts0, utils.ExecveEventType, `has(event.ttyMajor) && event.ttyMajor == uint(136)`))
	require.True(t, evalTTYEvent(t, pts0, utils.ExecveEventType, `event.hasTty`), "pts/0 has a terminal")
}

// TestCELHasTTY_NonExecEvent_DatasourceEvent asserts that has(event.hasTty) is
// false on a non-exec event whose datasource carries no tty field at all. The
// design intends this to be naturally false because presenceOf("tty") finds
// nothing to report — not because of any special-casing on event type.
func TestCELHasTTY_NonExecEvent_DatasourceEvent(t *testing.T) {
	noTTYFields := newDatasourceExecEvent(t, utils.OpenEventType, ttyDSFields{})
	require.False(t, evalTTYEvent(t, noTTYFields, utils.OpenEventType, `has(event.hasTty)`))
}

// TestCELTTYFieldsDatasourceEvent_WrongExpressionRejected proves the compile
// assertion in evalTTYEvent has teeth: a comparison against a bare integer
// literal for a uint-typed field must fail to compile (CEL here has no
// cross-type numeric comparison), so a typo cannot masquerade as a legitimate
// false. This is exercised directly against registerExpression rather than
// evalTTYEvent, since evalTTYEvent's require.NoError would itself fail the
// test if invoked with this expression — which is precisely the point.
func TestCELTTYFieldsDatasourceEvent_WrongExpressionRejected(t *testing.T) {
	c := newTestCEL(t)
	err := c.registerExpression(`event.ttyMajor == 136`)
	require.Error(t, err, "comparing a uint field against a bare int literal must fail to compile")
}
