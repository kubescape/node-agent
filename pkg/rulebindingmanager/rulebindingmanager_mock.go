package rulebindingmanager

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

var _ RuleBindingCache = (*RuleBindingCacheMock)(nil)

type RuleBindingCacheMock struct {
}

func (r *RuleBindingCacheMock) ListRulesForPod(_, _ string) []typesv1.RuleSpec {
	return []typesv1.RuleSpec{}
}
func (r *RuleBindingCacheMock) AddNotifier(_ *chan RuleBindingNotify) {
}

func (r *RuleBindingCacheMock) GetRuleCreator() rulecreator.RuleCreator {
	return nil
}

func (r *RuleBindingCacheMock) RefreshRuleBindingsRules() {
}
