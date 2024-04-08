package exporters

import (
	"github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"testing"
)

func TestPriorityToStatus(t *testing.T) {
	tests := []struct {
		name     string
		priority int
		want     string
	}{
		{
			name:     "none",
			priority: ruleengine.RulePriorityNone,
			want:     "none",
		},
		{
			name:     "low",
			priority: ruleengine.RulePriorityLow,
			want:     "low",
		},
		{
			name:     "medium",
			priority: ruleengine.RulePriorityMed,
			want:     "medium",
		},
		{
			name:     "high",
			priority: ruleengine.RulePriorityHigh,
			want:     "high",
		},
		{
			name:     "critical",
			priority: ruleengine.RulePriorityCritical,
			want:     "critical",
		},
		{
			name:     "system_issue",
			priority: ruleengine.RulePrioritySystemIssue,
			want:     "system_issue",
		},
		{
			name:     "unknown",
			priority: 100,
			want:     "unknown",
		},
		{
			name:     "low2",
			priority: ruleengine.RulePriorityMed - 1,
			want:     "low",
		},
		{
			name:     "medium2",
			priority: ruleengine.RulePriorityHigh - 1,
			want:     "medium",
		},
		{
			name:     "high2",
			priority: ruleengine.RulePriorityCritical - 1,
			want:     "high",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PriorityToStatus(tt.priority); got != tt.want {
				t.Errorf("PriorityToStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}
