package rulemanager

import (
	"context"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
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

// evidenceFailureCreator records the correlation hits each rule's alert was
// handed, keyed by rule ID, which is exactly the thing that must not leak
// between rules.
type evidenceFailureCreator struct {
	hits map[string][][]*rulestate.Entry
}

func (c *evidenceFailureCreator) CreateRuleFailure(rule typesv1.Rule, _ *events.EnrichedEvent, _ objectcache.ObjectCache, _, _, _ string, _ map[string]any, hits []*rulestate.Entry) types.RuleFailure {
	c.hits[rule.ID] = append(c.hits[rule.ID], hits)
	return &types.GenericRuleFailure{}
}

func evidenceExecEvent() *events.EnrichedEvent {
	return &events.EnrichedEvent{
		Event: &utils.StructEvent{
			EventType:   utils.ExecveEventType,
			ContainerID: "abc",
			Namespace:   "test",
			Pod:         "pod",
			Comm:        "sh",
			Pid:         4242,
		},
		ContainerID: "abc",
		PID:         4242,
		// The store stamps ExpiresAt from the resolved event time; a zero time
		// would make every entry expired at birth.
		Timestamp: time.Now(),
	}
}

// Rule A declares a marker and reads it; rule B declares nothing and alerts on
// every exec. The tracker is one object per event shared by every rule, so if
// it is reset only when the NEXT rule declares state, B's alert is handed A's
// hits as its own correlation evidence, although B never read state.
func TestReportEnrichedEvent_StatelessRuleGetsNoCorrelationEvidence(t *testing.T) {
	cfg := config.Config{HostMonitoringEnabled: true, StandaloneMonitoringEnabled: true}
	cfg.CelStateStore = rulestate.Config{
		Enabled: true, MaxSize: 1000, MaxEntriesPerContainer: 100,
		MaxEntriesForHost: 100, MaxTTL: 30 * time.Minute, AncestorMaxDepth: 8,
	}
	evaluator, err := cel.NewCEL(objectcache.NewObjectCacheMock(), cfg)
	require.NoError(t, err)
	store := rulestate.NewStore(cfg.CelStateStore, rulestate.NoopMetrics{})

	stateful := typesv1.Rule{
		RuntimeRule: armotypes.RuntimeRule{
			ID: "R9001", Enabled: true, ProfileDependency: armotypes.NotRequired,
			Tags: []string{"context:host", "context:container"},
			StateWrites: []armotypes.StateWrite{{
				EventType: armotypes.EventTypeExec, Scope: armotypes.StateScopeContainer,
				Name: "marker", TTL: "10m",
			}},
		},
		Expressions: typesv1.RuleExpressions{
			Message: "'stateful'", UniqueID: "'a'",
			RuleExpression: []typesv1.RuleExpression{{EventType: utils.ExecveEventType, Expression: `state.has("marker")`}},
		},
	}
	stateless := typesv1.Rule{
		RuntimeRule: armotypes.RuntimeRule{
			ID: "R9002", Enabled: true, ProfileDependency: armotypes.NotRequired,
			Tags: []string{"context:host", "context:container"},
		},
		Expressions: typesv1.RuleExpressions{
			Message: "'stateless'", UniqueID: "'b'",
			RuleExpression: []typesv1.RuleExpression{{EventType: utils.ExecveEventType, Expression: "true"}},
		},
	}

	creator := &evidenceFailureCreator{hits: map[string][][]*rulestate.Entry{}}
	rm := &RuleManager{
		ctx:                context.Background(),
		cfg:                cfg,
		ruleBindingCache:   &profileGateBindings{rules: []typesv1.Rule{stateful, stateless}},
		objectCache:        &stateObjectCacheFake{cpc: &profileGateCache{profile: &objectcache.ProjectedContainerProfile{}}},
		celEvaluator:       evaluator,
		exporter:           &profileGateExporter{},
		metrics:            &profileGateMetrics{},
		ruleCooldown:       rulecooldown.NewRuleCooldown(rulecooldown.RuleCooldownConfig{Disabled: true, MaxSize: 1}),
		alertLogDedup:      expirable.NewLRU[string, struct{}](8, nil, 0),
		ruleFailureCreator: creator,
		stateStore:         store,
		stateWrites:        statewrites.NewExecutor(store, evaluator, rulestate.NoopMetrics{}),
		stateWritesCache:   expirable.NewLRU[string, *compiledWrites](16, nil, 0),
	}
	rm.podToWlid.Set("test/pod", "workload")

	// First event: A's predicate misses (writes run after it) and the marker is
	// written. Second event: A reads the marker and alerts with one hit.
	rm.ReportEnrichedEvent(evidenceExecEvent())
	rm.ReportEnrichedEvent(evidenceExecEvent())

	require.Len(t, creator.hits["R9001"], 1, "the stateful rule alerts once, on the second event")
	assert.Len(t, creator.hits["R9001"][0], 1, "the stateful rule's alert cites the marker it read")

	require.Len(t, creator.hits["R9002"], 2, "the stateless rule alerts on both events")
	for i, hits := range creator.hits["R9002"] {
		assert.Empty(t, hits, "event %d: a rule that declares no state must carry no correlation evidence", i+1)
	}
}
