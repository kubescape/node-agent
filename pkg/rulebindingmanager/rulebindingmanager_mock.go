package rulebindingmanager

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

var _ RuleBindingCache = (*RuleBindingCacheMock)(nil)

type RuleBindingCacheMock struct {
}

func (r *RuleBindingCacheMock) ListRulesForPod(_, _ string) []types.Rule {
	return []types.Rule{}
}
func (r *RuleBindingCacheMock) AddNotifier(_ *chan RuleBindingNotify) {
}

func (r *RuleBindingCacheMock) GetRuleCreator() rulecreator.RuleCreator {
	return nil
}
