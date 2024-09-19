package ruleengine

import (
	"github.com/kubescape/node-agent/pkg/cooldown"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"

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

type RuleDescriptor struct {
	// Rule ID
	ID string
	// Rule Name
	Name string
	// Rule Description
	Description string
	// Priority
	Priority int
	// Tags
	Tags []string
	// Rule requirements
	Requirements RuleSpec
	// Create a rule function
	RuleCreationFunc func() RuleEvaluator
}

func (r *RuleDescriptor) HasTags(tags []string) bool {
	for _, tag := range tags {
		for _, ruleTag := range r.Tags {
			if tag == ruleTag {
				return true
			}
		}
	}
	return false
}

// RuleCreator is an interface for creating rules by tags, IDs, and names
type RuleCreator interface {
	CreateRulesByTags(tags []string) []RuleEvaluator
	CreateRuleByID(id string) RuleEvaluator
	CreateRuleByName(name string) RuleEvaluator
	RegisterRule(rule RuleDescriptor)
}

type RuleEvaluator interface {
	// Rule ID - this is the rules unique identifier
	ID() string

	// Rule Name
	Name() string

	// Rule processing
	ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) RuleFailure

	// Rule requirements
	Requirements() RuleSpec

	// Set rule parameters
	SetParameters(parameters map[string]interface{})

	// Get rule parameters
	GetParameters() map[string]interface{}

	// Cooldown configuration
	CooldownConfig() *cooldown.CooldownConfig
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
	// Get Rule ID
	GetRuleId() string
	// Get Failure identifier
	GetFailureIdentifier() string

	// Set Workload Details
	SetWorkloadDetails(workloadDetails string)
	// Set Base Runtime Alert
	SetBaseRuntimeAlert(baseRuntimeAlert apitypes.BaseRuntimeAlert)
	// Set Runtime Process Details
	SetRuntimeProcessDetails(runtimeProcessDetails apitypes.ProcessTree)
	// Set Trigger Event
	SetTriggerEvent(triggerEvent igtypes.Event)
	// Set Rule Description
	SetRuleAlert(ruleAlert apitypes.RuleAlert)
	// Set K8s Runtime Details
	SetRuntimeAlertK8sDetails(runtimeAlertK8sDetails apitypes.RuntimeAlertK8sDetails)
}
