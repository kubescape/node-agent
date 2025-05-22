package ruleengine

import (
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
)

var _ RuleCreator = (*RuleCreatorMock)(nil)

type RuleCreatorMock struct {
}

func (r *RuleCreatorMock) CreateRulesByTags(tags []string) []RuleEvaluator {
	var rl []RuleEvaluator
	for _, t := range tags {
		rl = append(rl, &RuleMock{RuleName: t})
	}
	return rl
}
func (r *RuleCreatorMock) CreateRuleByID(id string) RuleEvaluator {
	return &RuleMock{RuleID: id}
}

func (r *RuleCreatorMock) CreateRuleByName(name string) RuleEvaluator {
	return &RuleMock{RuleName: name}
}

func (r *RuleCreatorMock) RegisterRule(rule RuleDescriptor) {
}

func (r *RuleCreatorMock) CreateRulesByEventType(eventType utils.EventType) []RuleEvaluator {
	return []RuleEvaluator{}
}

func (r *RuleCreatorMock) CreateRulePolicyRulesByEventType(eventType utils.EventType) []RuleEvaluator {
	return []RuleEvaluator{}
}

func (r *RuleCreatorMock) CreateAllRules() []RuleEvaluator {
	return []RuleEvaluator{}
}

func (r *RuleCreatorMock) GetAllRuleIDs() []string {
	return []string{}
}

var _ RuleEvaluator = (*RuleMock)(nil)

type RuleMock struct {
	RuleRequirements RuleSpec
	RuleParameters   map[string]interface{}
	RuleName         string
	RuleID           string
}

func (rule *RuleMock) Name() string {
	return rule.RuleName
}

func (rule *RuleMock) ID() string {
	return rule.RuleID
}

func (rule *RuleMock) DeleteRule() {
}

func (rule *RuleMock) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{}) {
	return false, nil
}

func (rule *RuleMock) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (bool, interface{}, error) {
	return false, nil, nil
}

func (rule *RuleMock) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload interface{}) RuleFailure {
	return nil
}

func (rule *RuleMock) Requirements() RuleSpec {
	return rule.RuleRequirements
}
func (rule *RuleMock) GetParameters() map[string]interface{} {
	return rule.RuleParameters
}
func (rule *RuleMock) SetParameters(p map[string]interface{}) {
	rule.RuleParameters = p
}

var _ RuleSpec = (*RuleSpecMock)(nil)

type RuleSpecMock struct {
}

func (ruleSpec *RuleSpecMock) RequiredEventTypes() []utils.EventType {
	return []utils.EventType{}
}

func (ruleSpec *RuleSpecMock) GetProfileRequirements() ProfileRequirement {
	return ProfileRequirement{}
}
