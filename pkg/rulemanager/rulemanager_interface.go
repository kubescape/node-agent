package rulemanager

import (
	"sync"
)

const (
	RulePriorityNone        = 0
	RulePriorityLow         = 1
	RulePriorityMed         = 5
	RulePriorityHigh        = 8
	RulePriorityCritical    = 10
	RulePrioritySystemIssue = 1000
)

type RuleDesciptor struct {
	// Rule ID
	ID string
	// Rule Name.
	Name string
	// Rule Description.
	Description string
	// Priority.
	Priority int
	// Tags
	Tags []string
	// Rule requirements.
	Requirements RuleRequirements
	// Create a rule function.
	RuleCreationFunc func() Rule
}

var _ RuleDesciptor = (*Rule)(nil)

type BaseRule struct {
	// Mutex for protecting rule parameters.
	parametersMutex sync.RWMutex
	parameters      map[string]interface{}
}

func (rule *BaseRule) SetParameters(parameters map[string]interface{}) {
	rule.parametersMutex.Lock()
	defer rule.parametersMutex.Unlock()
	rule.parameters = parameters
}

func (rule *BaseRule) GetParameters() map[string]interface{} {
	rule.parametersMutex.RLock()
	defer rule.parametersMutex.RUnlock()
	if rule.parameters == nil {
		rule.parameters = make(map[string]interface{})
		return rule.parameters
	}

	// Create a copy to avoid returning a reference to the internal map
	parametersCopy := make(map[string]interface{})
	for key, value := range rule.parameters {
		parametersCopy[key] = value
	}

	return parametersCopy
}

func (r *RuleDesciptor) HasTags(tags []string) bool {
	for _, tag := range tags {
		for _, ruleTag := range r.Tags {
			if tag == ruleTag {
				return true
			}
		}
	}
	return false
}
