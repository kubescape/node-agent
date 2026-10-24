package rulemanager

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/contextdetection"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

type mockContextInfo struct {
	ctx        contextdetection.EventSourceContext
	workloadID string
}

func (m *mockContextInfo) Context() contextdetection.EventSourceContext { return m.ctx }
func (m *mockContextInfo) WorkloadID() string                           { return m.workloadID }

func TestRuleAppliesToContext(t *testing.T) {
	tests := []struct {
		name        string
		rule        typesv1.Rule
		contextInfo contextdetection.ContextInfo
		expected    bool
	}{
		{
			name:        "nil contextInfo: rule with no tags defaults to kubernetes",
			rule:        typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{Tags: []string{}}},
			contextInfo: nil,
			expected:    true,
		},
		{
			name:        "nil contextInfo: rule with host tag rejected",
			rule:        typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{Tags: []string{"context:host"}}},
			contextInfo: nil,
			expected:    false,
		},
		{
			name:        "nil contextInfo: rule with kubernetes tag accepted",
			rule:        typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{Tags: []string{"context:kubernetes"}}},
			contextInfo: nil,
			expected:    true,
		},
		{
			name:        "nil contextInfo: rule with container tag accepted (kubernetes is container-type)",
			rule:        typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{Tags: []string{"context:container"}}},
			contextInfo: nil,
			expected:    true,
		},
		{
			name:        "host context: host tag matches",
			rule:        typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{Tags: []string{"context:host"}}},
			contextInfo: &mockContextInfo{ctx: contextdetection.Host},
			expected:    true,
		},
		{
			name:        "host context: kubernetes tag rejected",
			rule:        typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{Tags: []string{"context:kubernetes"}}},
			contextInfo: &mockContextInfo{ctx: contextdetection.Host},
			expected:    false,
		},
		{
			name:        "host context: no tags rejected (backward compat = k8s only)",
			rule:        typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{Tags: []string{"other"}}},
			contextInfo: &mockContextInfo{ctx: contextdetection.Host},
			expected:    false,
		},

		{
			name:        "standalone context: standalone tag matches",
			rule:        typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{Tags: []string{"context:standalone"}}},
			contextInfo: &mockContextInfo{ctx: contextdetection.Standalone},
			expected:    true,
		},
		{
			name:        "standalone context: container meta-tag matches",
			rule:        typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{Tags: []string{"context:container"}}},
			contextInfo: &mockContextInfo{ctx: contextdetection.Standalone},
			expected:    true,
		},
		{
			name:        "ecs context: ecs tag matches",
			rule:        typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{Tags: []string{"context:ecs"}}},
			contextInfo: &mockContextInfo{ctx: contextdetection.ECS},
			expected:    true,
		},
		{
			name:        "ecs context: host tag rejected",
			rule:        typesv1.Rule{RuntimeRule: armotypes.RuntimeRule{Tags: []string{"context:host"}}},
			contextInfo: &mockContextInfo{ctx: contextdetection.ECS},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RuleAppliesToContext(&tt.rule, tt.contextInfo)
			if result != tt.expected {
				t.Errorf("RuleAppliesToContext() = %v, want %v", result, tt.expected)
			}
		})
	}
}
