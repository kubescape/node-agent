package rulebindingmanager

import "node-agent/pkg/ruleengine"

var _ RuleBindingCache = (*RuleBindingCacheMock)(nil)

type RuleBindingCacheMock struct {
}

func NewRuleBindingCacheMock() *RuleBindingCacheMock {
	return &RuleBindingCacheMock{}
}
func (r *RuleBindingCacheMock) ListRulesForPod(namespace, name string) []ruleengine.RuleEvaluator {
	return []ruleengine.RuleEvaluator{}
}
func (r *RuleBindingCacheMock) AddNotifier(_ *chan RuleBindingNotify) {
}

func (r *RuleBindingCacheMock) IsCached(namespace, name string) bool {
	return false
}
