package rulebindingmanager

import (
	"node-agent/pkg/ruleengine"
)

type RuleBindingCache interface {
	ListRulesForPod(namespace, name string) []ruleengine.RuleEvaluator
	AddNotifier(*chan RuleBindingNotify)
}
