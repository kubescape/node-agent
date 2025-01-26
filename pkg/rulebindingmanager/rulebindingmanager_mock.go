package rulebindingmanager

import "github.com/kubescape/node-agent/pkg/ruleengine"

var _ RuleBindingCache = (*RuleBindingCacheMock)(nil)

type RuleBindingCacheMock struct {
}

func (r *RuleBindingCacheMock) NewRuleBinding(_ string, _ []string) RuleBindingCache {
	return &RuleBindingCacheMock{}
}

func (r *RuleBindingCacheMock) ListRulesForPod(_, _ string) []ruleengine.RuleEvaluator {
	return []ruleengine.RuleEvaluator{}
}
func (r *RuleBindingCacheMock) AddNotifier(_ *chan RuleBindingNotify) {
}

func (r *RuleBindingCacheMock) GetRuleCreator() ruleengine.RuleCreator {
	return nil
}
