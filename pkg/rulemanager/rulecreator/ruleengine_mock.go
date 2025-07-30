package rulecreator

import (
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

var _ RuleCreator = (*RuleCreatorMock)(nil)

type RuleCreatorMock struct {
	Rules []typesv1.Rule
}

func (r *RuleCreatorMock) CreateRulesByTags(tags []string) []typesv1.Rule {
	var rl []typesv1.Rule
	for _, t := range tags {
		rl = append(rl, typesv1.Rule{
			Name: t,
			Tags: []string{t},
		})
	}
	return rl
}

func (r *RuleCreatorMock) CreateRuleByID(id string) typesv1.Rule {
	return typesv1.Rule{
		ID: id,
	}
}

func (r *RuleCreatorMock) CreateRuleByName(name string) typesv1.Rule {
	return typesv1.Rule{
		Name: name,
	}
}

func (r *RuleCreatorMock) RegisterRule(rule typesv1.Rule) {
}

func (r *RuleCreatorMock) CreateRulesByEventType(eventType utils.EventType) []typesv1.Rule {
	return []typesv1.Rule{}
}

func (r *RuleCreatorMock) CreateRulePolicyRulesByEventType(eventType utils.EventType) []typesv1.Rule {
	return []typesv1.Rule{}
}

func (r *RuleCreatorMock) CreateAllRules() []typesv1.Rule {
	return []typesv1.Rule{}
}

func (r *RuleCreatorMock) GetAllRuleIDs() []string {
	var ids []string
	for _, rule := range r.Rules {
		ids = append(ids, rule.ID)
	}
	return ids
}

// Dynamic rule management methods for CRD sync
func (r *RuleCreatorMock) SyncRules(newRules []typesv1.Rule) {
	r.Rules = newRules
}

func (r *RuleCreatorMock) RemoveRuleByID(id string) bool {
	for i, rule := range r.Rules {
		if rule.ID == id {
			r.Rules = append(r.Rules[:i], r.Rules[i+1:]...)
			return true
		}
	}
	return false
}

func (r *RuleCreatorMock) UpdateRule(rule typesv1.Rule) bool {
	for i, existingRule := range r.Rules {
		if existingRule.ID == rule.ID {
			r.Rules[i] = rule
			return true
		}
	}
	r.Rules = append(r.Rules, rule)
	return false
}

func (r *RuleCreatorMock) HasRule(id string) bool {
	for _, rule := range r.Rules {
		if rule.ID == id {
			return true
		}
	}
	return false
}
