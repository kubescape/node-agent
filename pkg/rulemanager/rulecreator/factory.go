package rulecreator

import (
	"slices"

	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

var _ RuleCreator = (*RuleCreatorImpl)(nil)

type RuleCreatorImpl struct {
	Rules []types.Rule
}

func NewRuleCreator() *RuleCreatorImpl {
	return &RuleCreatorImpl{}
}

func (r *RuleCreatorImpl) CreateRulesByTags(tags []string) []types.Rule {
	var rules []types.Rule
	for _, rule := range r.Rules {
		for _, tag := range tags {
			if slices.Contains(rule.Tags, tag) {
				rules = append(rules, rule)
				break
			}
		}
	}
	return rules
}

func (r *RuleCreatorImpl) CreateRuleByID(id string) types.Rule {
	for _, rule := range r.Rules {
		if rule.ID == id {
			return rule
		}
	}
	return types.Rule{}
}

func (r *RuleCreatorImpl) CreateRuleByName(name string) types.Rule {
	for _, rule := range r.Rules {
		if rule.Name == name {
			return rule
		}
	}
	return types.Rule{}
}

func (r *RuleCreatorImpl) RegisterRule(rule types.Rule) {
	r.Rules = append(r.Rules, rule)
}

func (r *RuleCreatorImpl) CreateRulesByEventType(eventType utils.EventType) []types.Rule {
	var rules []types.Rule
	for _, rule := range r.Rules {
		for _, expression := range rule.Expressions.RuleExpression {
			if expression.EventType == eventType {
				rules = append(rules, rule)
				break
			}
		}
	}
	return rules
}

func (r *RuleCreatorImpl) CreateRulePolicyRulesByEventType(eventType utils.EventType) []types.Rule {
	rules := r.CreateRulesByEventType(eventType)
	for _, rule := range rules {
		if rule.SupportPolicy {
			rules = append(rules, rule)
		}
	}

	return rules
}

func (r *RuleCreatorImpl) GetAllRuleIDs() []string {
	var ruleIDs []string
	for _, rule := range r.Rules {
		ruleIDs = append(ruleIDs, rule.ID)
	}
	return ruleIDs
}

func (r *RuleCreatorImpl) CreateAllRules() []types.Rule {
	var rules []types.Rule
	for _, rule := range r.Rules {
		rules = append(rules, rule)
	}
	return rules
}

func containsEventType(eventTypes []utils.EventType, eventType utils.EventType) bool {
	for _, et := range eventTypes {
		if et == eventType {
			return true
		}
	}
	return false
}
