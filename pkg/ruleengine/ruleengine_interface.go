package ruleengine

import (
	"node-agent/pkg/objectcache"
	"node-agent/pkg/utils"
)

const (
	RulePriorityNone        = 0
	RulePriorityLow         = 1
	RulePriorityMed         = 5
	RulePriorityHigh        = 8
	RulePriorityCritical    = 10
	RulePrioritySystemIssue = 1000
)

// RuleCreator is an interface for creating rules by tags, IDs, and names
type RuleCreator interface {
	CreateRulesByTags(tags []string) []RuleEvaluator
	CreateRuleByID(id string) RuleEvaluator
	CreateRuleByName(name string) RuleEvaluator
}

type RuleEvaluator interface {

	// Rule ID - this is the rules unique identifier
	ID() string

	// Rule Name
	Name() string

	// Rule processing
	ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) RuleFailure

	// Rule requirements
	Requirements() RuleSpec

	// Set rule parameters
	SetParameters(parameters map[string]interface{})

	// Get rule parameters
	GetParameters() map[string]interface{}
}

// RuleSpec is an interface for rule requirements
type RuleSpec interface {
	// Event types required for the rule
	RequiredEventTypes() []utils.EventType

	// Some rules need an application profile
	IsApplicationProfileRequired() bool
}

type RuleFailure interface {
	// Rule Name.
	Name() string

	// Rule ID.
	ID() string

	// ContainerID() string

	// Priority.
	Priority() int
	// Error interface.
	Error() string
	// Fix suggestion.
	FixSuggestion() string
	// Generic event
	Event() *utils.GeneralEvent
}
