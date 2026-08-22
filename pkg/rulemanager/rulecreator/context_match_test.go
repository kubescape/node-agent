package rulecreator

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/contextdetection"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

func TestRuleMatchesContext(t *testing.T) {
	tests := []struct {
		name     string
		rule     typesv1.Rule
		context  contextdetection.EventSourceContext
		expected bool
	}{
		{
			name:     "host tag matches host context",
			rule:     typesv1.Rule{Tags: []string{"context:host"}},
			context:  contextdetection.Host,
			expected: true,
		},
		{
			name:     "host tag does not match kubernetes context",
			rule:     typesv1.Rule{Tags: []string{"context:host"}},
			context:  contextdetection.Kubernetes,
			expected: false,
		},
		{
			name:     "kubernetes tag matches kubernetes context",
			rule:     typesv1.Rule{Tags: []string{"context:kubernetes"}},
			context:  contextdetection.Kubernetes,
			expected: true,
		},
		{
			name:     "kubernetes tag does not match host context",
			rule:     typesv1.Rule{Tags: []string{"context:kubernetes"}},
			context:  contextdetection.Host,
			expected: false,
		},
		{
			name:     "standalone tag matches standalone context",
			rule:     typesv1.Rule{Tags: []string{"context:standalone"}},
			context:  contextdetection.Standalone,
			expected: true,
		},
		{
			name:     "ecs tag matches ecs context",
			rule:     typesv1.Rule{Tags: []string{"context:ecs"}},
			context:  contextdetection.ECS,
			expected: true,
		},
		{
			name:     "container tag matches kubernetes context",
			rule:     typesv1.Rule{Tags: []string{"context:container"}},
			context:  contextdetection.Kubernetes,
			expected: true,
		},
		{
			name:     "container tag matches standalone context",
			rule:     typesv1.Rule{Tags: []string{"context:container"}},
			context:  contextdetection.Standalone,
			expected: true,
		},
		{
			name:     "container tag matches ecs context",
			rule:     typesv1.Rule{Tags: []string{"context:container"}},
			context:  contextdetection.ECS,
			expected: true,
		},
		{
			name:     "container tag matches container context",
			rule:     typesv1.Rule{Tags: []string{"context:container"}},
			context:  contextdetection.Container,
			expected: true,
		},
		{
			name:     "container tag does not match host context",
			rule:     typesv1.Rule{Tags: []string{"context:container"}},
			context:  contextdetection.Host,
			expected: false,
		},

		{
			name:     "no context tags defaults to kubernetes",
			rule:     typesv1.Rule{Tags: []string{"some-other-tag"}},
			context:  contextdetection.Kubernetes,
			expected: true,
		},
		{
			name:     "no context tags rejects host",
			rule:     typesv1.Rule{Tags: []string{"some-other-tag"}},
			context:  contextdetection.Host,
			expected: false,
		},
		{
			name:     "no context tags rejects standalone",
			rule:     typesv1.Rule{Tags: []string{}},
			context:  contextdetection.Standalone,
			expected: false,
		},
		{
			name:     "nil tags defaults to kubernetes",
			rule:     typesv1.Rule{},
			context:  contextdetection.Kubernetes,
			expected: true,
		},
		{
			name:     "nil tags rejects host",
			rule:     typesv1.Rule{},
			context:  contextdetection.Host,
			expected: false,
		},

		{
			name:     "multiple context tags: host+kubernetes matches host",
			rule:     typesv1.Rule{Tags: []string{"context:host", "context:kubernetes"}},
			context:  contextdetection.Host,
			expected: true,
		},
		{
			name:     "multiple context tags: host+kubernetes matches kubernetes",
			rule:     typesv1.Rule{Tags: []string{"context:host", "context:kubernetes"}},
			context:  contextdetection.Kubernetes,
			expected: true,
		},
		{
			name:     "multiple context tags: host+kubernetes rejects standalone",
			rule:     typesv1.Rule{Tags: []string{"context:host", "context:kubernetes"}},
			context:  contextdetection.Standalone,
			expected: false,
		},

		{
			name:     "mixed tags with context:host matches host",
			rule:     typesv1.Rule{Tags: []string{"severity:high", "context:host", "category:network"}},
			context:  contextdetection.Host,
			expected: true,
		},
		{
			name:     "mixed tags with context:host rejects kubernetes",
			rule:     typesv1.Rule{Tags: []string{"severity:high", "context:host", "category:network"}},
			context:  contextdetection.Kubernetes,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RuleMatchesContext(&tt.rule, tt.context)
			if result != tt.expected {
				t.Errorf("RuleMatchesContext() = %v, want %v (rule tags: %v, context: %s)",
					result, tt.expected, tt.rule.Tags, tt.context)
			}
		})
	}
}
