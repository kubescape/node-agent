package rulebindingmanager

import "node-agent/pkg/ruleengine"

var _ RuleBindingCache = (*RuleBindingCacheMock)(nil)

type RuleBindingCacheMock struct {
}

func (r *RuleBindingCacheMock) ListRulesForPod(_, _ string) []ruleengine.RuleEvaluator {
	return []ruleengine.RuleEvaluator{}
}
func (r *RuleBindingCacheMock) AddNotifier(_ *chan RuleBindingNotify) {
}
