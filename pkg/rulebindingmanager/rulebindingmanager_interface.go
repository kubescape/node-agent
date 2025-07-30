package rulebindingmanager

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

type RuleBindingCache interface {
	ListRulesForPod(namespace, name string) []typesv1.Rule
	AddNotifier(*chan RuleBindingNotify)
	GetRuleCreator() rulecreator.RuleCreator
	RefreshRuleBindingsRules()
}
