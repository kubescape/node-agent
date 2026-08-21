package rulecreator

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/contextdetection"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

func testRules() []typesv1.Rule {
	return []typesv1.Rule{
		{ID: "host-only", Name: "Host Rule", Enabled: true, Tags: []string{"context:host"}},
		{ID: "k8s-only", Name: "K8s Rule", Enabled: true, Tags: []string{"context:kubernetes"}},
		{ID: "standalone-only", Name: "Standalone Rule", Enabled: true, Tags: []string{"context:standalone"}},
		{ID: "ecs-only", Name: "ECS Rule", Enabled: true, Tags: []string{"context:ecs"}},
		{ID: "container-meta", Name: "Container Rule", Enabled: true, Tags: []string{"context:container"}},
		{ID: "no-context", Name: "Legacy Rule", Enabled: true, Tags: []string{"severity:high"}},
		{ID: "multi-context", Name: "Multi Context", Enabled: true, Tags: []string{"context:host", "context:standalone"}},
	}
}

func TestCreateRulesForContext(t *testing.T) {
	tests := []struct {
		name        string
		context     contextdetection.EventSourceContext
		expectedIDs []string
	}{
		{
			name:    "host context returns host-only and multi-context rules",
			context: contextdetection.Host,
			expectedIDs: []string{
				"host-only",
				"multi-context",
			},
		},
		{
			name:    "kubernetes context returns k8s-only, container-meta, and no-context (backward compat)",
			context: contextdetection.Kubernetes,
			expectedIDs: []string{
				"k8s-only",
				"container-meta",
				"no-context",
			},
		},
		{
			name:    "standalone context returns standalone-only, container-meta, and multi-context",
			context: contextdetection.Standalone,
			expectedIDs: []string{
				"standalone-only",
				"container-meta",
				"multi-context",
			},
		},
		{
			name:    "ecs context returns ecs-only and container-meta",
			context: contextdetection.ECS,
			expectedIDs: []string{
				"ecs-only",
				"container-meta",
			},
		},
		{
			name:    "container context returns container-meta only",
			context: contextdetection.Container,
			expectedIDs: []string{
				"container-meta",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creator := &RuleCreatorImpl{Rules: testRules()}
			rules := creator.CreateRulesForContext(tt.context)

			gotIDs := make(map[string]bool)
			for _, r := range rules {
				gotIDs[r.ID] = true
			}

			expectedSet := make(map[string]bool)
			for _, id := range tt.expectedIDs {
				expectedSet[id] = true
			}

			for _, id := range tt.expectedIDs {
				if !gotIDs[id] {
					t.Errorf("expected rule %q to be included for context %s, but it was not", id, tt.context)
				}
			}

			for _, r := range rules {
				if !expectedSet[r.ID] {
					t.Errorf("unexpected rule %q included for context %s", r.ID, tt.context)
				}
			}

			if len(rules) != len(tt.expectedIDs) {
				t.Errorf("got %d rules, want %d", len(rules), len(tt.expectedIDs))
			}

		})
	}
}

func TestCreateRulesForContext_PrefilterInitialized(t *testing.T) {
	creator := &RuleCreatorImpl{
		Rules: []typesv1.Rule{
			{
				ID:      "host-rule",
				Enabled: true,
				Tags:    []string{"context:host"},
				State: map[string]any{
					"ports": []uint16{443},
				},
			},
		},
	}

	rules := creator.CreateRulesForContext(contextdetection.Host)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if rules[0].Prefilter == nil {
		t.Error("expected Prefilter to be initialized, got nil")
	}
}

func TestCreateRulesForContext_EmptyRules(t *testing.T) {
	creator := &RuleCreatorImpl{Rules: []typesv1.Rule{}}
	rules := creator.CreateRulesForContext(contextdetection.Host)
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for empty creator, got %d", len(rules))
	}
}

func TestCreateRulesForContext_NoMatchingRules(t *testing.T) {
	creator := &RuleCreatorImpl{
		Rules: []typesv1.Rule{
			{ID: "k8s-only", Tags: []string{"context:kubernetes"}},
		},
	}
	rules := creator.CreateRulesForContext(contextdetection.Host)
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for non-matching context, got %d", len(rules))
	}
}

func TestCreateRulesForContext_ConsistentWithRuleMatchesContext(t *testing.T) {
	allContexts := []contextdetection.EventSourceContext{
		contextdetection.Kubernetes,
		contextdetection.Host,
		contextdetection.Standalone,
		contextdetection.Container,
		contextdetection.ECS,
	}

	allRules := testRules()
	creator := &RuleCreatorImpl{Rules: allRules}

	for _, ctx := range allContexts {
		t.Run(string(ctx), func(t *testing.T) {
			filteredRules := creator.CreateRulesForContext(ctx)
			filteredIDs := make(map[string]bool)
			for _, r := range filteredRules {
				filteredIDs[r.ID] = true
			}

			for i := range allRules {
				expected := RuleMatchesContext(&allRules[i], ctx)
				got := filteredIDs[allRules[i].ID]

				if expected != got {
					t.Errorf("inconsistency for rule %q in context %s: RuleMatchesContext=%v, CreateRulesForContext included=%v",
						allRules[i].ID, ctx, expected, got)
				}
			}
		})
	}
}
