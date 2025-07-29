package rulecreator

import (
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

var _ RuleCreator = (*RuleCreatorMock)(nil)

type RuleCreatorMock struct {
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
	return []string{}
}
