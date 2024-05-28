package rulebindingmanager

import (
	"node-agent/pkg/ruleengine"
)

type RuleBindingCache interface {
	ListRulesForPod(namespace, podName string) []ruleengine.RuleEvaluator
	AddNotifier(*chan RuleBindingNotify)
}
