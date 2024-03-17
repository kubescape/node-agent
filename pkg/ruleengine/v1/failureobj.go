package ruleengine

import (
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
)

var _ ruleengine.RuleFailure = (*GenericRuleFailure)(nil)

type GenericRuleFailure struct {
	RuleName         string
	RulePriority     int
	FixSuggestionMsg string
	Err              string
	FailureEvent     *utils.GeneralEvent
}

func (rule *GenericRuleFailure) Name() string {
	return rule.RuleName
}

func (rule *GenericRuleFailure) Error() string {
	return rule.Err
}

func (rule *GenericRuleFailure) Event() *utils.GeneralEvent {
	return rule.FailureEvent
}

func (rule *GenericRuleFailure) Priority() int {
	return rule.RulePriority
}

func (rule *GenericRuleFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
