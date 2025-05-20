package ruleengine

import (
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
	// RulePolicySupport indicates if the rule supports policy
	RulePolicySupport bool
}

// ProfileRequirement indicates how a rule uses profiles
type ProfileRequirement struct {
	// ProfileDependency indicates if the rule requires a profile
	ProfileDependency apitypes.ProfileDependency

	// ProfileType indicates what type of profile is needed (Application, Network, etc)
	ProfileType apitypes.ProfileType
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
	CreateRulesByEventType(eventType utils.EventType) []RuleEvaluator
	CreateRulePolicyRulesByEventType(eventType utils.EventType) []RuleEvaluator
	CreateAllRules() []RuleEvaluator
	GetAllRuleIDs() []string
}

type RuleEvaluator interface {
	// Rule ID - this is the rules unique identifier
	ID() string

	// Rule Name
	Name() string

	// EvaluateRule evaluates the rule without profile
	EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{})

	// EvaluateRuleWithProfile evaluates the rule with profile
	EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (bool, interface{}, error)

	// CreateRuleFailure creates a rule failure
	CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) RuleFailure

	// Rule requirements
	Requirements() RuleSpec

	// Set rule parameters
	SetParameters(parameters map[string]interface{})

	// Get rule parameters
	GetParameters() map[string]interface{}
}

type RuleCondition interface {
	EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{})
	ID() string
}

// RuleSpec is an interface for rule requirements
type RuleSpec interface {
	// Event types required for the rule
	RequiredEventTypes() []utils.EventType

	// Profile requirements
	GetProfileRequirements() ProfileRequirement
}

type RuleFailure interface {
	// Get Base Runtime Alert
	GetBaseRuntimeAlert() apitypes.BaseRuntimeAlert
	// Get Alert Type
	GetAlertType() apitypes.AlertType
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
	// Get Cloud Services
	GetCloudServices() []string
	// Get Http Details
	GetHttpRuleAlert() apitypes.HttpRuleAlert
	// Get Alert Platform
	GetAlertPlatform() apitypes.AlertSourcePlatform
	// Get Extra
	GetExtra() interface{}

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
	// Set Cloud Services
	SetCloudServices(cloudServices []string)
	// Set Alert Platform
	SetAlertPlatform(alertPlatform apitypes.AlertSourcePlatform)
}
