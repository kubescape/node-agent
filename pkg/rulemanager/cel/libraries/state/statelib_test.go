package state

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRuleID = "R1089"

// harness evaluates CEL expressions against a real store and a real cel.Env, so
// the tests exercise the actual dispatch path rather than the impl functions.
type harness struct {
	t         *testing.T
	env       *cel.Env
	store     *rulestate.Store
	tracker   *ReadTracker
	scopeID   string
	ancestors []uint32
	// scopeOf stands in for the rule's own stateWrites declarations, which is
	// what tells a read which scope a name lives in.
	scopeOf map[string]armotypes.StateScope
	now     time.Time
}

func newHarness(t *testing.T) *harness {
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

	env, err := cel.NewEnv(
		cel.Variable("timestamp", cel.TimestampType),
		State(cfg),
	)
	require.NoError(t, err)

	return &harness{
		t:       t,
		env:     env,
		store:   rulestate.NewStore(cfg.CelStateStore, rulestate.NoopMetrics{}),
		tracker: &ReadTracker{},
		scopeID: "c:abc",
		scopeOf: map[string]armotypes.StateScope{},
		now:     time.Now(),
	}
}

// write stores an entry and declares its name as container-scoped, mirroring what
// a rule's stateWrites clause would have done at load time.
//
// ts sets the entry's logical event time, which tests compare against. ExpiresAt
// is deliberately derived from wall-clock now instead: expiry is enforced against
// time.Now(), so deriving it from a ts in the past (any fixed date literal, since
// these tests use them) would store an already-expired entry and every read would
// miss for a reason that has nothing to do with what is being tested.
func (h *harness) write(ruleID, scopeID, name, key string, ts time.Time) *rulestate.Entry {
	h.t.Helper()
	e := &rulestate.Entry{
		RuleID: ruleID, Name: name, Key: key,
		Scope: armotypes.StateScopeContainer, ScopeID: scopeID,
		EventType: armotypes.EventTypeExec,
		Timestamp: ts, ExpiresAt: time.Now().Add(10 * time.Minute),
		Process: &armotypes.Process{
			PID: 4471, PPID: 900, Comm: "xmrig", Pcomm: "sh",
			Path: "/mnt/data/xmrig", Cwd: "/mnt/data",
		},
	}
	require.NoError(h.t, h.store.Set(e))
	h.scopeOf[name] = armotypes.StateScopeContainer
	return e
}

func (h *harness) accessor() *Accessor {
	return NewAccessor(
		h.store, testRuleID, h.scopeOf,
		map[armotypes.StateScope]string{armotypes.StateScopeContainer: h.scopeID},
		func() []uint32 { return h.ancestors },
		h.tracker,
		types.DefaultTypeAdapter,
	)
}

func (h *harness) eval(expr string) any {
	h.t.Helper()
	ast, iss := h.env.Compile(expr)
	require.NoError(h.t, iss.Err(), "expression must compile: %s", expr)

	prg, err := h.env.Program(ast)
	require.NoError(h.t, err)

	out, _, err := prg.Eval(map[string]any{
		AccessorContextKey: h.accessor(),
		"timestamp":        h.now.Add(time.Minute),
	})
	require.NoError(h.t, err, "expression must not error: %s", expr)
	return out.Value()
}

func (h *harness) evalBool(expr string) bool {
	h.t.Helper()
	v, ok := h.eval(expr).(bool)
	require.True(h.t, ok, "expression must yield a bool: %s", expr)
	return v
}

func (h *harness) evalString(expr string) string {
	h.t.Helper()
	v, ok := h.eval(expr).(string)
	require.True(h.t, ok, "expression must yield a string: %s", expr)
	return v
}

func TestStateHas_HitAndMiss(t *testing.T) {
	h := newHarness(t)
	h.write(testRuleID, "c:abc", "mount_exec", "4471", time.Now())

	assert.True(t, h.evalBool(`state.has("mount_exec", "4471")`))
	assert.False(t, h.evalBool(`state.has("mount_exec", "9999")`))
	assert.False(t, h.evalBool(`state.has("nope", "4471")`))
}

func TestStateHas_OneArgFormForScopeWideMarkers(t *testing.T) {
	h := newHarness(t)
	h.write(testRuleID, "c:abc", "pkg_mgr_ran", "", time.Now())
	assert.True(t, h.evalBool(`state.has("pkg_mgr_ran")`))
}

func TestStateGet_ExposesProvenanceAndAuthorValues(t *testing.T) {
	h := newHarness(t)
	ts := time.Date(2026, 7, 28, 12, 0, 3, 100000000, time.UTC)
	e := h.write(testRuleID, "c:abc", "mount_exec", "4471", ts)
	e.Value = map[string]any{"argv": "-o pool:4444"}

	assert.Equal(t, "xmrig", h.evalString(`state.get("mount_exec", "4471")._comm`))
	assert.Equal(t, "sh", h.evalString(`state.get("mount_exec", "4471")._pcomm`))
	assert.Equal(t, "/mnt/data/xmrig", h.evalString(`state.get("mount_exec", "4471")._exe`))
	assert.Equal(t, "/mnt/data", h.evalString(`state.get("mount_exec", "4471")._cwd`))
	assert.Equal(t, "exec", h.evalString(`state.get("mount_exec", "4471")._eventType`))
	assert.Equal(t, "-o pool:4444", h.evalString(`state.get("mount_exec", "4471").argv`))
}

// _ts must be a CEL timestamp, not a string: the whole ordering-guard idiom is a
// comparison against the current event's time.
func TestStateGet_TimestampIsComparable(t *testing.T) {
	h := newHarness(t)
	h.now = time.Date(2026, 7, 28, 12, 0, 3, 0, time.UTC)
	h.write(testRuleID, "c:abc", "mount_exec", "4471", h.now)

	assert.True(t, h.evalBool(`state.get("mount_exec", "4471")._ts < timestamp`),
		"the remembered event happened before the current one")
}

func TestStateGet_MissReturnsEmptyMapNotError(t *testing.T) {
	h := newHarness(t)
	// A message expression must degrade, not fail evaluation.
	assert.Equal(t, int64(0), h.eval(`size(state.get("absent", "1"))`))
}

// A miss must not make a provenance access blow up the whole predicate -- this is
// the difference between a rule that under-fires and a rule that errors out.
func TestStateGet_MissTolerated_WithHasGuard(t *testing.T) {
	h := newHarness(t)
	assert.False(t, h.evalBool(
		`state.has("absent", "1") && state.get("absent", "1")._pid == 1u`))
}

func TestStateHasAncestor_MatchesAnAncestorPID(t *testing.T) {
	h := newHarness(t)
	// nginx 900 -> sh 4471 -> curl 4530; marker is on 4471.
	h.ancestors = []uint32{4471, 900, 1}
	h.write(testRuleID, "c:abc", "webshell_parent", "4471", time.Now())

	assert.True(t, h.evalBool(`state.has_ancestor("webshell_parent")`))
	assert.Equal(t, "xmrig", h.evalString(`state.get_ancestor("webshell_parent")._comm`))
}

func TestStateHasAncestor_NoMatchWhenNoAncestorCarriesTheMarker(t *testing.T) {
	h := newHarness(t)
	h.ancestors = []uint32{5000, 5001}
	h.write(testRuleID, "c:abc", "webshell_parent", "4471", time.Now())
	assert.False(t, h.evalBool(`state.has_ancestor("webshell_parent")`))
}

func TestStateHasAncestor_WorksWithHostScope(t *testing.T) {
	h := newHarness(t)
	h.scopeID = rulestate.HostScopeID()
	h.ancestors = []uint32{2200, 1}
	h.write(testRuleID, rulestate.HostScopeID(), "sudo_ran", "2200", time.Now())
	assert.True(t, h.evalBool(`state.has_ancestor("sudo_ran")`))
}

// get_ancestor must return the NEAREST match, since the ancestor list is ordered
// nearest-first and a chain can carry the marker at several depths.
func TestStateGetAncestor_ReturnsNearestMatch(t *testing.T) {
	h := newHarness(t)
	h.ancestors = []uint32{4471, 900}

	near := h.write(testRuleID, "c:abc", "marker", "4471", time.Now())
	near.Process = &armotypes.Process{PID: 4471, Comm: "near"}
	far := h.write(testRuleID, "c:abc", "marker", "900", time.Now())
	far.Process = &armotypes.Process{PID: 900, Comm: "far"}

	assert.Equal(t, "near", h.evalString(`state.get_ancestor("marker")._comm`))
}

func TestStateHasAncestor_EmptyAncestorListIsAMiss(t *testing.T) {
	h := newHarness(t)
	h.ancestors = nil
	h.write(testRuleID, "c:abc", "marker", "4471", time.Now())
	assert.False(t, h.evalBool(`state.has_ancestor("marker")`))
}

func TestReadTracker_RecordsOnlyEntriesActuallyRead(t *testing.T) {
	h := newHarness(t)
	h.write(testRuleID, "c:abc", "mount_exec", "4471", time.Now())
	h.write(testRuleID, "c:abc", "unrelated", "4471", time.Now())

	require.True(t, h.evalBool(`state.has("mount_exec", "4471")`))
	hits := h.tracker.Hits()
	require.Len(t, hits, 1, "only the entry the predicate touched is evidence")
	assert.Equal(t, "mount_exec", hits[0].Name)
}

func TestReadTracker_MissesAreNotRecorded(t *testing.T) {
	h := newHarness(t)
	require.False(t, h.evalBool(`state.has("absent", "1")`))
	assert.Empty(t, h.tracker.Hits())
}

func TestReadTracker_ResetClearsBetweenRules(t *testing.T) {
	h := newHarness(t)
	h.write(testRuleID, "c:abc", "mount_exec", "4471", time.Now())
	require.True(t, h.evalBool(`state.has("mount_exec", "4471")`))
	require.Len(t, h.tracker.Hits(), 1)

	h.tracker.Reset()
	assert.Empty(t, h.tracker.Hits(),
		"without a per-rule reset, rule N inherits rule N-1's evidence")
}

// Reading the same entry twice in one predicate must cite it once.
func TestReadTracker_DeduplicatesRepeatedReads(t *testing.T) {
	h := newHarness(t)
	h.write(testRuleID, "c:abc", "mount_exec", "4471", time.Now())
	require.True(t, h.evalBool(
		`state.has("mount_exec", "4471") && state.get("mount_exec", "4471")._pid == 4471u`))
	assert.Len(t, h.tracker.Hits(), 1)
}

func TestState_RuleIDIsNotExpressible(t *testing.T) {
	h := newHarness(t)
	// Stored under a DIFFERENT rule; the harness evaluates as R1089. There is no
	// CEL syntax for naming another rule's state, which is what makes state
	// rule-private.
	h.write("R9999", "c:abc", "mount_exec", "4471", time.Now())
	assert.False(t, h.evalBool(`state.has("mount_exec", "4471")`))
}

// The neighbouring-container case, same argument as above: the scope ID comes
// from the receiver, so no expression can reach another container's bucket.
func TestState_ScopeIDIsNotExpressible(t *testing.T) {
	h := newHarness(t)
	h.write(testRuleID, "c:other", "mount_exec", "4471", time.Now())
	assert.False(t, h.evalBool(`state.has("mount_exec", "4471")`))
}

// A name the rule never declared has no scope to resolve against, so it reads as
// a miss instead of erroring.
func TestState_UndeclaredNameIsAMiss(t *testing.T) {
	h := newHarness(t)
	h.write(testRuleID, "c:abc", "declared", "1", time.Now())
	delete(h.scopeOf, "declared")
	assert.False(t, h.evalBool(`state.has("declared", "1")`))
}

func TestState_ExpiredEntryIsAMiss(t *testing.T) {
	h := newHarness(t)
	e := h.write(testRuleID, "c:abc", "mount_exec", "4471", time.Now())
	e.ExpiresAt = time.Now().Add(-time.Second)
	assert.False(t, h.evalBool(`state.has("mount_exec", "4471")`))
}

// The library declares member functions called "has" -- the same identifier as
// CEL's built-in has() macro. If declaring it ever shadowed the macro,
// has(event.field) would break across every existing rule.
func TestState_DoesNotShadowTheHasMacro(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("m", cel.MapType(cel.StringType, cel.StringType)),
		State(config.Config{}),
	)
	require.NoError(t, err)

	ast, iss := env.Compile(`has(m.present)`)
	require.NoError(t, iss.Err(), "the has() macro must still parse alongside state.has")

	prg, err := env.Program(ast)
	require.NoError(t, err)

	out, _, err := prg.Eval(map[string]any{"m": map[string]string{"present": "x"}})
	require.NoError(t, err)
	assert.Equal(t, true, out.Value())
}
