package rulecreator

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

var _ RuleCreator = (*RuleCreatorMock)(nil)

type RuleCreatorMock struct {
}

func (r *RuleCreatorMock) CreateRulesByTags(tags []string) []types.Rule {
	var rl []types.Rule
	for _, t := range tags {
		rl = append(rl, types.Rule{
			Name: t,
			Tags: []string{t},
		})
	}
	return rl
}

func (r *RuleCreatorMock) CreateRuleByID(id string) types.Rule {
	return types.Rule{
		ID: id,
	}
}

func (r *RuleCreatorMock) CreateRuleByName(name string) types.Rule {
	return types.Rule{
		Name: name,
	}
}

func (r *RuleCreatorMock) RegisterRule(rule types.Rule) {
}

func (r *RuleCreatorMock) CreateRulesByEventType(eventType utils.EventType) []types.Rule {
	return []types.Rule{}
}

func (r *RuleCreatorMock) CreateRulePolicyRulesByEventType(eventType utils.EventType) []types.Rule {
	return []types.Rule{}
}

func (r *RuleCreatorMock) CreateAllRules() []types.Rule {
	return []types.Rule{}
}

func (r *RuleCreatorMock) GetAllRuleIDs() []string {
	return []string{}
}
