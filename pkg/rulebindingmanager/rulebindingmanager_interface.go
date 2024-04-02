package rulebindingmanager

import "node-agent/pkg/ruleengine"

type RuleBindingCache interface {
	IsCached(kind, namespace, name string) bool
	ListRulesForPod(namespace, name string) []ruleengine.RuleEvaluator
}
