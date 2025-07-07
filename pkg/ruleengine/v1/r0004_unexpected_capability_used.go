package ruleengine

import (
	"fmt"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/goradd/maps"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	R0004ID   = "R0004"
	R0004Name = "Unexpected capability used"
)

var R0004UnexpectedCapabilityUsedRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R0004ID,
	Name:        R0004Name,
	Description: "Detecting unexpected capabilities that are not whitelisted by application profile. Every unexpected capability is identified in context of a syscall and will be alerted only once per container.",
	Tags:        []string{"capabilities", "whitelisted"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.CapabilitiesEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0004UnexpectedCapabilityUsed()
	},
}
var _ ruleengine.RuleEvaluator = (*R0004UnexpectedCapabilityUsed)(nil)

type R0004UnexpectedCapabilityUsed struct {
	BaseRule
	alertedCapabilities maps.SafeMap[string, bool]
}

func CreateRuleR0004UnexpectedCapabilityUsed() *R0004UnexpectedCapabilityUsed {
	return &R0004UnexpectedCapabilityUsed{}
}
func (rule *R0004UnexpectedCapabilityUsed) Name() string {
	return R0004Name
}

func (rule *R0004UnexpectedCapabilityUsed) ID() string {
	return R0004ID
}

func (rule *R0004UnexpectedCapabilityUsed) DeleteRule() {
}

func (rule *R0004UnexpectedCapabilityUsed) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.CapabilitiesEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	capEvent, ok := event.(*tracercapabilitiestype.Event)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	if rule.alertedCapabilities.Has(capEvent.CapName) {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	return ruleengine.DetectionResult{IsFailure: true, Payload: capEvent.CapName}
}

func (rule *R0004UnexpectedCapabilityUsed) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return detectionResult, nil
	}

	capEventTyped, _ := event.(*tracercapabilitiestype.Event)
	ap, err := GetApplicationProfile(capEventTyped.Runtime.ContainerID, objCache)
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	appProfileCapabilitiesList, err := GetContainerFromApplicationProfile(ap, capEventTyped.GetContainer())
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	for _, capability := range appProfileCapabilitiesList.Capabilities {
		if capEventTyped.CapName == capability {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
		}
	}

	return detectionResult, nil
}

func (rule *R0004UnexpectedCapabilityUsed) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	capEvent, _ := event.(*tracercapabilitiestype.Event)
	rule.alertedCapabilities.Set(capEvent.CapName, true)

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(fmt.Sprintf("%s%s", capEvent.Comm, capEvent.CapName)),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"syscall":    capEvent.Syscall,
				"capability": capEvent.CapName,
			},
			InfectedPID: capEvent.Pid,
			Severity:    R0004UnexpectedCapabilityUsedRuleDescriptor.Priority,
			Identifiers: &common.Identifiers{
				Process: &common.ProcessEntity{
					Name: capEvent.Comm,
				},
			},
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: capEvent.Comm,
				Gid:  &capEvent.Gid,
				PID:  capEvent.Pid,
				Uid:  &capEvent.Uid,
			},
			ContainerID: capEvent.Runtime.ContainerID,
		},
		TriggerEvent: capEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Unexpected capability used (capability %s used in syscall %s)", capEvent.CapName, capEvent.Syscall),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName: capEvent.GetPod(),
		},
		RuleID: rule.ID(),
	}
}

func (rule *R0004UnexpectedCapabilityUsed) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0004UnexpectedCapabilityUsedRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Required,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
