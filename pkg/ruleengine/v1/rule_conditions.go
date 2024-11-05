package ruleengine

import (
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
)

func EvaluateRulesForEvent(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache, ruleCreator *RuleCreatorImpl) []string {
	results := []string{}
	rules := ruleCreator.CreateRulesByEventType(eventType)

	for _, rule := range rules {
		rule, ok := rule.(ruleengine.RuleCondition)
		if !ok {
			continue
		}

		if rule.EvaluateRule(eventType, event, k8sObjCache) {
			results = append(results, rule.ID())
		}
	}

	return results
}
