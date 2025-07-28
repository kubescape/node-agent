package rulebindingmanager

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

type RuleBindingCache interface {
	ListRulesForPod(namespace, name string) []types.Rule
	AddNotifier(*chan RuleBindingNotify)
	GetRuleCreator() rulecreator.RuleCreator
}
