package exporters

import (
	"github.com/kubescape/node-agent/pkg/ruleengine/v1"
)

func PriorityToStatus(priority int) string {
	switch priority {
	case ruleengine.RulePriorityNone:
		return "none"
	case ruleengine.RulePriorityLow:
		return "low"
	case ruleengine.RulePriorityMed:
		return "medium"
	case ruleengine.RulePriorityHigh:
		return "high"
	case ruleengine.RulePriorityCritical:
		return "critical"
	case ruleengine.RulePrioritySystemIssue:
		return "system_issue"
	default:
		if priority < ruleengine.RulePriorityMed {
			return "low"
		} else if priority < ruleengine.RulePriorityHigh {
			return "medium"
		} else if priority < ruleengine.RulePriorityCritical {
			return "high"
		}
		return "unknown"
	}
}
