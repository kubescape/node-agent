package rulecreator

import (
	"slices"

	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

var _ RuleCreator = (*RuleCreatorImpl)(nil)

type RuleCreatorImpl struct {
	Rules []typesv1.RuleSpec
}

func NewRuleCreator() *RuleCreatorImpl {
	return &RuleCreatorImpl{}
}

func (r *RuleCreatorImpl) CreateRulesByTags(tags []string) []typesv1.RuleSpec {
	var rules []typesv1.RuleSpec
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

func (r *RuleCreatorImpl) CreateRuleByID(id string) typesv1.RuleSpec {
	for _, rule := range r.Rules {
		if rule.ID == id {
			return rule
		}
	}
	return typesv1.RuleSpec{}
}

func (r *RuleCreatorImpl) CreateRuleByName(name string) typesv1.RuleSpec {
	for _, rule := range r.Rules {
		if rule.Name == name {
			return rule
		}
	}
	return typesv1.RuleSpec{}
}

func (r *RuleCreatorImpl) RegisterRule(rule typesv1.RuleSpec) {
	r.Rules = append(r.Rules, rule)
}

func (r *RuleCreatorImpl) CreateRulesByEventType(eventType utils.EventType) []typesv1.RuleSpec {
	var rules []typesv1.RuleSpec
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

func (r *RuleCreatorImpl) CreateRulePolicyRulesByEventType(eventType utils.EventType) []typesv1.RuleSpec {
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

func (r *RuleCreatorImpl) CreateAllRules() []typesv1.RuleSpec {
	var rules []typesv1.RuleSpec
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
