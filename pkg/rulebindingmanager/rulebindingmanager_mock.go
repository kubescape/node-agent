package rulebindingmanager

import "node-agent/pkg/ruleengine"

var _ RuleBindingCache = (*RuleBindingCacheMock)(nil)

type RuleBindingCacheMock struct {
	Rules map[string][]ruleengine.RuleEvaluator
}

func (r *RuleBindingCacheMock) ListRulesForPod(namespace, name string) []ruleengine.RuleEvaluator {
	return r.Rules[namespace+"/"+name]
}
