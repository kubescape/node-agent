package ruleengine

import (
	"node-agent/pkg/objectcache"
	"node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
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
}

type RuleFailure interface {
	// Get Base Runtime Alert
	GetBaseRuntimeAlert() apitypes.BaseRuntimeAlert
	// Get Runtime Process Details
	GetRuntimeProcessDetails() apitypes.ProcessTree
	// Get Trigger Event
	GetTriggerEvent() igtypes.Event
	// Get Rule Description
	GetRuleAlert() apitypes.RuleAlert
	// Get K8s Runtime Details
	GetRuntimeAlertK8sDetails() apitypes.RuntimeAlertK8sDetails

	// Set Workload Details
	SetWorkloadDetails(workloadDetails string)
}
