package ruleengine

import (
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
)

func ProcessRuleEvaluationTest(rule ruleengine.RuleEvaluator, eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	// First check if we need profile evaluation
	if rule.Requirements().GetProfileRequirements().Required || rule.Requirements().GetProfileRequirements().Optional {
		ok, _ := rule.EvaluateRuleWithProfile(eventType, event, objCache)
		if !ok {
			return nil
		}
	}

	// If profile is not required, do basic evaluation
	if !rule.Requirements().GetProfileRequirements().Required {
		ok, _ := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
		if !ok {
			return nil
		}
	}

	// Create and return the failure
	return rule.CreateRuleFailure(eventType, event, objCache)
}
