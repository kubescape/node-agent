package ruleengine

import (
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/goradd/maps"
)

const (
	RulePriorityNone        = 0
	RulePriorityLow         = 1
	RulePriorityMed         = 5
	RulePriorityHigh        = 8
	RulePriorityCritical    = 10
	RulePrioritySystemIssue = 1000
)

var _ ruleengine.RuleSpec = (*RuleRequirements)(nil)

type RuleRequirements struct {
	// Needed events for the rule.
	EventTypes []utils.EventType
	// Profile requirements
	ProfileRequirements ruleengine.ProfileRequirement
}

// Event types required for the rule
func (r *RuleRequirements) RequiredEventTypes() []utils.EventType {
	return r.EventTypes
}

// Profile requirements
func (r *RuleRequirements) GetProfileRequirements() ruleengine.ProfileRequirement {
	return r.ProfileRequirements
}

type BaseRule struct {
	// Mutex for protecting rule parameters.
	parameters maps.SafeMap[string, interface{}]
}

func (br *BaseRule) SetParameters(parameters map[string]interface{}) {
	for k, v := range parameters {
		br.parameters.Set(k, v)
	}
}

func (br *BaseRule) GetParameters() map[string]interface{} {

	// Create a copy to avoid returning a reference to the internal map
	parametersCopy := make(map[string]interface{}, br.parameters.Len())

	br.parameters.Range(
		func(key string, value interface{}) bool {
			parametersCopy[key] = value
			return true
		},
	)
	return parametersCopy
}

// Basic evaluation without profile
func (br *BaseRule) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, _ objectcache.K8sObjectCache) (bool, interface{}) {
	return false, nil
}

// Evaluation with profile if available
func (br *BaseRule) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (bool, interface{}) {
	return false, nil
}

// Create rule failure with available context
func (br *BaseRule) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	return nil
}
