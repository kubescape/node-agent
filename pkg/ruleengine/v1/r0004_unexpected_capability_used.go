package ruleengine

import (
	"fmt"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
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

func (rule *R0004UnexpectedCapabilityUsed) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.CapabilitiesEventType {
		return nil
	}

	capEvent, ok := event.(*tracercapabilitiestype.Event)
	if !ok {
		return nil
	}

	ap := objCache.ApplicationProfileCache().GetApplicationProfile(capEvent.Runtime.ContainerID)
	if ap == nil {
		return nil
	}

	appProfileCapabilitiesList, err := GetContainerFromApplicationProfile(ap, capEvent.GetContainer())
	if err != nil {
		return nil
	}

	if rule.alertedCapabilities.Has(capEvent.CapName) {
		return nil
	}

	for _, capability := range appProfileCapabilitiesList.Capabilities {
		if capEvent.CapName == capability {
			return nil
		}
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(fmt.Sprintf("%s%s", capEvent.Comm, capEvent.CapName)),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"syscall":    capEvent.Syscall,
				"capability": capEvent.CapName,
			},
			InfectedPID: capEvent.Pid,
			Severity:    R0004UnexpectedCapabilityUsedRuleDescriptor.Priority,
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

	rule.alertedCapabilities.Set(capEvent.CapName, true)

	return &ruleFailure
}

func (rule *R0004UnexpectedCapabilityUsed) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0004UnexpectedCapabilityUsedRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
