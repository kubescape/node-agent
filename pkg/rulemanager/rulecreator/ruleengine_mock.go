package rulecreator

import (
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

var _ RuleCreator = (*RuleCreatorMock)(nil)

type RuleCreatorMock struct {
	Rules []typesv1.RuleSpec
}

func (r *RuleCreatorMock) CreateRulesByTags(tags []string) []typesv1.RuleSpec {
	var rl []typesv1.RuleSpec
	for _, t := range tags {
		rl = append(rl, typesv1.RuleSpec{
			Name: t,
			Tags: []string{t},
		})
	}
	return rl
}

func (r *RuleCreatorMock) CreateRuleByID(id string) typesv1.RuleSpec {
	return typesv1.RuleSpec{
		ID: id,
	}
}

func (r *RuleCreatorMock) CreateRuleByName(name string) typesv1.RuleSpec {
	return typesv1.RuleSpec{
		Name: name,
	}
}

func (r *RuleCreatorMock) RegisterRule(rule typesv1.RuleSpec) {
}

func (r *RuleCreatorMock) CreateRulesByEventType(eventType utils.EventType) []typesv1.RuleSpec {
	return []typesv1.RuleSpec{}
}

func (r *RuleCreatorMock) CreateRulePolicyRulesByEventType(eventType utils.EventType) []typesv1.RuleSpec {
	return []typesv1.RuleSpec{}
}

func (r *RuleCreatorMock) CreateAllRules() []typesv1.RuleSpec {
	return []typesv1.RuleSpec{}
}

func (r *RuleCreatorMock) GetAllRuleIDs() []string {
	var ids []string
	for _, rule := range r.Rules {
		ids = append(ids, rule.ID)
	}
	return ids
}

// Dynamic rule management methods for CRD sync
func (r *RuleCreatorMock) SyncRules(newRules []typesv1.RuleSpec) {
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

func (r *RuleCreatorMock) UpdateRule(rule typesv1.RuleSpec) bool {
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
