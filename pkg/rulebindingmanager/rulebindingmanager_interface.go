package rulebindingmanager

import (
	"github.com/kubescape/node-agent/pkg/ruleengine"
)

type RuleBindingCache interface {
	ListRulesForPod(namespace, name string) []ruleengine.RuleEvaluator
	AddNotifier(*chan RuleBindingNotify)
}
