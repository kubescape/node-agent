package rulepolicy

import (
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
)

type RulePolicyReporter struct {
	ruleManager             rulemanager.RuleManagerClient
	containerProfileManager containerprofilemanager.ContainerProfileManagerClient
}

func NewRulePolicyReporter(ruleManager rulemanager.RuleManagerClient, containerProfileManager containerprofilemanager.ContainerProfileManagerClient) *RulePolicyReporter {
	return &RulePolicyReporter{
		ruleManager:             ruleManager,
		containerProfileManager: containerProfileManager,
	}
}

func (rpm *RulePolicyReporter) ReportEvent(eventType utils.EventType, event utils.K8sEvent, containerID string, allowedProcess string) {
	rulesIds := rpm.ruleManager.EvaluatePolicyRulesForEvent(eventType, event)
	for _, rule := range rulesIds {
		rpm.containerProfileManager.ReportRulePolicy(containerID, rule, allowedProcess, false)
	}
}
