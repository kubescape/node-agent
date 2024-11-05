package rulepolicy

import (
	"github.com/kubescape/node-agent/pkg/applicationprofilemanager"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
)

type RulePolicyReporter struct {
	ruleManager               rulemanager.RuleManagerClient
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient
}

func NewRulePolicyReporter(ruleManager rulemanager.RuleManagerClient, applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient) *RulePolicyReporter {
	return &RulePolicyReporter{
		ruleManager:               ruleManager,
		applicationProfileManager: applicationProfileManager,
	}
}

func (rpm *RulePolicyReporter) ReportEvent(eventType utils.EventType, event utils.K8sEvent, k8sContainerID string, allowedProcess string) {
	rulesIds := rpm.ruleManager.EvaluateRulesForEvent(eventType, event)
	for _, rule := range rulesIds {
		// TODO: Add a check to see if the rule is using rule policy 
		rpm.applicationProfileManager.ReportRulePolicy(k8sContainerID, rule, allowedProcess, false)
	}
}
