package rulemanager

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/contextdetection"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecooldown"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

type profileGateContext contextdetection.EventSourceContext

func (c profileGateContext) Context() contextdetection.EventSourceContext {
	return contextdetection.EventSourceContext(c)
}
func (c profileGateContext) WorkloadID() string { return "workload" }

type profileGateEvent struct{ utils.K8sEvent }

func (profileGateEvent) GetNamespace() string          { return "test" }
func (profileGateEvent) GetPod() string                { return "pod" }
func (profileGateEvent) GetEventType() utils.EventType { return utils.ExecveEventType }

type profileGateCache struct {
	objectcache.ContainerProfileCache
	profile *objectcache.ProjectedContainerProfile
}

func (c *profileGateCache) GetProjectedContainerProfile(string) *objectcache.ProjectedContainerProfile {
	return c.profile
}

type profileGateBindings struct {
	rulebindingmanager.RuleBindingCacheMock
	rules []typesv1.Rule
}

func (b *profileGateBindings) ListRulesForPod(string, string) []typesv1.Rule { return b.rules }
func (b *profileGateBindings) GetRuleCreator() rulecreator.RuleCreator {
	return &rulecreator.RuleCreatorMock{Rules: b.rules}
}

type profileGateEvaluator struct {
	cel.RuleEvaluator
	evaluations int
}

func (e *profileGateEvaluator) CreateEvalContext(*events.EnrichedEvent) map[string]any {
	return map[string]any{}
}
func (e *profileGateEvaluator) EvaluateRuleWithContext(map[string]any, utils.EventType, []typesv1.RuleExpression) (bool, error) {
	e.evaluations++
	return true, nil
}
func (e *profileGateEvaluator) EvaluateExpression(*events.EnrichedEvent, string) (string, error) {
	return "alert", nil
}

type profileGateExporter struct {
	exporters.ExporterMock
	alerts int
}

func (e *profileGateExporter) SendRuleAlert(types.RuleFailure) { e.alerts++ }

type profileGateFailureCreator struct{}

func (profileGateFailureCreator) CreateRuleFailure(typesv1.Rule, *events.EnrichedEvent, objectcache.ObjectCache, string, string, string, map[string]any) types.RuleFailure {
	return &types.GenericRuleFailure{}
}

type profileGateMetrics struct {
	metricsmanager.MetricsMock
	suppressed []string
}

func (m *profileGateMetrics) ReportAlertSuppressed(ruleID, reason string) {
	m.suppressed = append(m.suppressed, ruleID+":"+reason)
}

func TestReportEnrichedEventProfileDependency(t *testing.T) {
	contexts := []struct {
		name        string
		source      contextdetection.ContextInfo
		containerID string
	}{
		{"host", profileGateContext(contextdetection.Host), "host"},
		{"standalone", profileGateContext(contextdetection.Standalone), "container"},
		{"kubernetes", profileGateContext(contextdetection.Kubernetes), "container"},
		{"legacy kubernetes", nil, "container"},
	}
	cases := []struct {
		name       string
		dependency armotypes.ProfileDependency
		profile    *objectcache.ProjectedContainerProfile
		wantAlerts int
	}{
		{"required missing", armotypes.Required, nil, 0},
		{"required available", armotypes.Required, &objectcache.ProjectedContainerProfile{}, 1},
		{"optional missing", armotypes.Optional, nil, 1},
		{"optional available", armotypes.Optional, &objectcache.ProjectedContainerProfile{}, 1},
		{"not required missing", armotypes.NotRequired, nil, 1},
		{"not required available", armotypes.NotRequired, &objectcache.ProjectedContainerProfile{}, 1},
	}
	for _, ctx := range contexts {
		for _, tc := range cases {
			t.Run(ctx.name+"/"+tc.name, func(t *testing.T) {
				evaluator := &profileGateEvaluator{}
				exporter := &profileGateExporter{}
				metrics := &profileGateMetrics{}
				rule := typesv1.Rule{
					ID: "R1059", Enabled: true, ProfileDependency: tc.dependency,
					Tags:        []string{"context:host", "context:container"},
					Expressions: typesv1.RuleExpressions{RuleExpression: []typesv1.RuleExpression{{EventType: utils.ExecveEventType, Expression: "true"}}},
				}
				rm := &RuleManager{
					ctx:              context.Background(),
					cfg:              config.Config{HostMonitoringEnabled: true, StandaloneMonitoringEnabled: true},
					ruleBindingCache: &profileGateBindings{rules: []typesv1.Rule{rule}},
					objectCache:      &stateObjectCacheFake{cpc: &profileGateCache{profile: tc.profile}},
					celEvaluator:     evaluator, exporter: exporter, metrics: metrics,
					ruleCooldown:       rulecooldown.NewRuleCooldown(rulecooldown.RuleCooldownConfig{Disabled: true, MaxSize: 1}),
					alertLogDedup:      expirable.NewLRU[string, struct{}](1, nil, 0),
					ruleFailureCreator: profileGateFailureCreator{},
				}
				rm.podToWlid.Set("test/pod", "workload")
				rm.ReportEnrichedEvent(&events.EnrichedEvent{Event: profileGateEvent{}, ContainerID: ctx.containerID, SourceContext: ctx.source})
				assert.Equal(t, tc.wantAlerts, evaluator.evaluations, "profile gate must precede evaluation")
				assert.Equal(t, tc.wantAlerts, exporter.alerts, "missing required profiles must not export alerts")
				if tc.wantAlerts == 0 {
					assert.Equal(t, []string{"R1059:profile_incomplete"}, metrics.suppressed)
				} else {
					assert.Empty(t, metrics.suppressed)
				}
			})
		}
	}
}
