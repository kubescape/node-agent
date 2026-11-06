package rulemanager

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecooldown"
	"github.com/kubescape/node-agent/pkg/rulemanager/statewrites"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/rulestate"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// counterAlert is one alert the loop emitted: which event (by pid), the
// message the rule rendered, and the state entries it cited.
type counterAlert struct {
	pid     uint32
	message string
	hits    []*rulestate.Entry
}

// counterFailureCreator is safe for concurrent use; the concurrency test below
// drives the loop from many goroutines.
type counterFailureCreator struct {
	mu     sync.Mutex
	alerts map[string][]counterAlert
}

func (c *counterFailureCreator) CreateRuleFailure(rule typesv1.Rule, ev *events.EnrichedEvent, _ objectcache.ObjectCache, message, _, _ string, _ map[string]any, hits []*rulestate.Entry) types.RuleFailure {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts[rule.ID] = append(c.alerts[rule.ID], counterAlert{pid: ev.PID, message: message, hits: hits})
	return &types.GenericRuleFailure{}
}

func (c *counterFailureCreator) of(ruleID string) []counterAlert {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]counterAlert(nil), c.alerts[ruleID]...)
}

type silentExporter struct{ exporters.ExporterMock }

func (*silentExporter) SendRuleAlert(types.RuleFailure) {}

func counterExecEvent(pid uint32) *events.EnrichedEvent {
	return &events.EnrichedEvent{
		Event: &utils.StructEvent{
			EventType: utils.ExecveEventType, ContainerID: "abc",
			Namespace: "test", Pod: "pod", Comm: "sh", Pid: pid,
		},
		ContainerID: "abc",
		PID:         pid,
		Timestamp:   time.Now(),
	}
}

func counterRule(id string, writes []armotypes.StateWrite, expression, message string) typesv1.Rule {
	return typesv1.Rule{
		RuntimeRule: armotypes.RuntimeRule{
			ID: id, Enabled: true, ProfileDependency: armotypes.NotRequired,
			Tags:        []string{"context:host", "context:container"},
			StateWrites: writes,
		},
		Expressions: typesv1.RuleExpressions{
			Message: message, UniqueID: "'u'",
			RuleExpression: []typesv1.RuleExpression{{EventType: utils.ExecveEventType, Expression: expression}},
		},
	}
}

func intp(i int) *int    { return &i }
func boolp(b bool) *bool { return &b }

func incrementWrite(name, key, when string) armotypes.StateWrite {
	return armotypes.StateWrite{
		EventType: armotypes.EventTypeExec, Scope: armotypes.StateScopeContainer,
		Name: name, Key: key, When: when, Increment: intp(1), TTL: "10m",
	}
}

func clearWrite(name, key, when string) armotypes.StateWrite {
	return armotypes.StateWrite{
		EventType: armotypes.EventTypeExec, Scope: armotypes.StateScopeContainer,
		Name: name, Key: key, When: when, Clear: boolp(true),
	}
}

func setWrite(name, key, when string) armotypes.StateWrite {
	return armotypes.StateWrite{
		EventType: armotypes.EventTypeExec, Scope: armotypes.StateScopeContainer,
		Name: name, Key: key, When: when, TTL: "10m",
	}
}

func newCounterManager(t *testing.T, rules ...typesv1.Rule) (*RuleManager, *counterFailureCreator, *rulestate.Store) {
	t.Helper()
	cfg := config.Config{HostMonitoringEnabled: true, StandaloneMonitoringEnabled: true}
	cfg.CelStateStore = rulestate.Config{
		Enabled: true, MaxSize: 100000, MaxEntriesPerContainer: 256,
		MaxEntriesForHost: 4096, MaxTTL: 30 * time.Minute, AncestorMaxDepth: 8,
	}
	evaluator, err := cel.NewCEL(objectcache.NewObjectCacheMock(), cfg)
	require.NoError(t, err)
	store := rulestate.NewStore(cfg.CelStateStore, rulestate.NoopMetrics{})
	creator := &counterFailureCreator{alerts: map[string][]counterAlert{}}
	rm := &RuleManager{
		ctx:                context.Background(),
		cfg:                cfg,
		ruleBindingCache:   &profileGateBindings{rules: rules},
		objectCache:        &stateObjectCacheFake{cpc: &profileGateCache{profile: &objectcache.ProjectedContainerProfile{}}},
		celEvaluator:       evaluator,
		exporter:           &silentExporter{},
		metrics:            &metricsmanager.MetricsNoop{},
		ruleCooldown:       rulecooldown.NewRuleCooldown(rulecooldown.RuleCooldownConfig{Disabled: true, MaxSize: 1}),
		alertLogDedup:      expirable.NewLRU[string, struct{}](1024, nil, 0),
		ruleFailureCreator: creator,
		stateStore:         store,
		stateWrites:        statewrites.NewExecutor(store, evaluator, rulestate.NoopMetrics{}),
		stateWritesCache:   expirable.NewLRU[string, *compiledWrites](16, nil, 0),
	}
	rm.podToWlid.Set("test/pod", "workload")
	return rm, creator, store
}

const key = "string(event.pid)"

func TestRuleLoop_TenthEventSeesTen(t *testing.T) {
	rule := counterRule("R1",
		[]armotypes.StateWrite{incrementWrite("n", "", "")},
		`state.count("n") == 10`,
		`string(state.count("n"))`)
	rm, creator, _ := newCounterManager(t, rule)

	for i := 1; i <= 12; i++ {
		rm.ReportEnrichedEvent(counterExecEvent(uint32(i)))
	}

	alerts := creator.of("R1")
	require.Len(t, alerts, 1, "== 10 fires exactly once")
	assert.Equal(t, uint32(10), alerts[0].pid, "on the tenth event, because the count includes this event")
	assert.Equal(t, "10", alerts[0].message)
}

func TestRuleLoop_ClearAfterThresholdResetsWindow(t *testing.T) {
	rule := counterRule("R1",
		[]armotypes.StateWrite{
			incrementWrite("n", key, ""),
			clearWrite("n", key, `state.count("n", string(event.pid)) >= 3`),
		},
		`state.count("n", string(event.pid)) >= 3`,
		`string(state.count("n", string(event.pid)))`)
	rm, creator, _ := newCounterManager(t, rule)

	for i := 0; i < 6; i++ {
		rm.ReportEnrichedEvent(counterExecEvent(7))
	}

	alerts := creator.of("R1")
	require.Len(t, alerts, 2, ">= 3 with a clear alerts on events 3 and 6, not 4 or 5")
	assert.Equal(t, "3", alerts[0].message)
	assert.Equal(t, "3", alerts[1].message)
}

func TestRuleLoop_IncrementGuardSeesPreIncrementCount(t *testing.T) {
	rule := counterRule("R1",
		[]armotypes.StateWrite{incrementWrite("n", key, `state.count("n", string(event.pid)) < 2`)},
		`false`, `''`)
	rm, _, store := newCounterManager(t, rule)

	for i := 0; i < 5; i++ {
		rm.ReportEnrichedEvent(counterExecEvent(7))
	}

	e, ok := store.Get("R1", "c:abc", "n", "7")
	require.True(t, ok)
	assert.Equal(t, int64(2), e.Count, "the guard reads the count before its own increment, so it stops at 2")
}

// A read made inside an increment's guard is not what the expression read, so
// it must not be cited as the alert's evidence.
func TestRuleLoop_IncrementGuardReadIsNotEvidence(t *testing.T) {
	rule := counterRule("R1",
		[]armotypes.StateWrite{
			incrementWrite("n", key, `!state.has("m", string(event.pid))`),
			setWrite("m", key, ""),
		},
		`state.count("n", string(event.pid)) >= 1`,
		`''`)
	rm, creator, _ := newCounterManager(t, rule)

	rm.ReportEnrichedEvent(counterExecEvent(7))
	rm.ReportEnrichedEvent(counterExecEvent(7))

	alerts := creator.of("R1")
	require.Len(t, alerts, 2)
	second := alerts[1]
	require.Len(t, second.hits, 1, "the second event's guard read the marker m, the expression read only n")
	assert.Equal(t, "n", second.hits[0].Name)
	assert.Equal(t, int64(1), second.hits[0].Count, "the marker blocked the second increment")
}

// Review Focus 3: a clear guarded on the counter it clears sees the
// post-increment snapshot, so it runs on the event that crossed the threshold.
func TestRuleLoop_ClearGuardSeesSnapshot(t *testing.T) {
	rule := counterRule("R1",
		[]armotypes.StateWrite{
			incrementWrite("n", key, ""),
			clearWrite("n", key, `state.count("n", string(event.pid)) == 3`),
		},
		`false`, `''`)
	rm, _, store := newCounterManager(t, rule)

	rm.ReportEnrichedEvent(counterExecEvent(7))
	rm.ReportEnrichedEvent(counterExecEvent(7))
	e, ok := store.Get("R1", "c:abc", "n", "7")
	require.True(t, ok)
	require.Equal(t, int64(2), e.Count)

	rm.ReportEnrichedEvent(counterExecEvent(7))
	_, ok = store.Get("R1", "c:abc", "n", "7")
	assert.False(t, ok, "the third event incremented to 3 and its clear saw 3")
}

func TestRuleLoop_EvidenceCarriesCount(t *testing.T) {
	rule := counterRule("R1",
		[]armotypes.StateWrite{incrementWrite("n", key, "")},
		`state.count("n", string(event.pid)) == 2`, `''`)
	rm, creator, _ := newCounterManager(t, rule)

	rm.ReportEnrichedEvent(counterExecEvent(7))
	rm.ReportEnrichedEvent(counterExecEvent(7))

	alerts := creator.of("R1")
	require.Len(t, alerts, 1)
	require.Len(t, alerts[0].hits, 1)
	assert.Equal(t, int64(2), alerts[0].hits[0].Count, "evidence shows the count as of the read")
}

// The proof of the snapshot: N events on N goroutines each observe a distinct
// count, and exactly one observes N. Without the snapshot two events could
// both read the same store value and `== N` could never be relied on.
func TestRuleLoop_ConcurrentEventsObserveDistinctCounts(t *testing.T) {
	const n = 32
	exact := counterRule("R1",
		[]armotypes.StateWrite{incrementWrite("n", "", "")},
		fmt.Sprintf(`state.count("n") == %d`, n), `''`)
	every := counterRule("R2",
		[]armotypes.StateWrite{incrementWrite("c", "", "")},
		`state.count("c") > 0`, `string(state.count("c"))`)
	rm, creator, _ := newCounterManager(t, exact, every)

	var wg sync.WaitGroup
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()
			rm.ReportEnrichedEvent(counterExecEvent(pid))
		}(uint32(i))
	}
	wg.Wait()

	assert.Len(t, creator.of("R1"), 1, "exactly one event observes N")

	seen := map[string]int{}
	for _, a := range creator.of("R2") {
		seen[a.message]++
	}
	require.Len(t, creator.of("R2"), n)
	assert.Len(t, seen, n, "every event observed a distinct count: %v", seen)
	assert.Equal(t, 1, seen[fmt.Sprint(n)])
}
