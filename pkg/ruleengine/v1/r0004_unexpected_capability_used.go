package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R0004ID   = "R0004"
	R0004Name = "Unexpected capability used"
)

var R0004UnexpectedCapabilityUsedRuleDescriptor = RuleDescriptor{
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

func (rule *R0004UnexpectedCapabilityUsed) generatePatchCommand(event *tracercapabilitiestype.Event, ap *v1beta1.ApplicationProfile) string {
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"capabilities\": [{\"syscall\": \"%s\", \"caps\": [%s]}]}]}}'"
	return fmt.Sprintf(baseTemplate, ap.GetName(), ap.GetNamespace(),
		event.GetContainer(), event.Syscall, event.CapName)
}

func (rule *R0004UnexpectedCapabilityUsed) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
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

	appProfileCapabilitiesList, err := getContainerFromApplicationProfile(ap, capEvent.GetContainer())
	if err != nil {
		return nil
	}

	for _, cap := range appProfileCapabilitiesList.Capabilities {
		if capEvent.CapName == cap {
			return nil
		}
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      rule.Name(),
			InfectedPID:    capEvent.Pid,
			FixSuggestions: fmt.Sprintf("If this is a valid behavior, please add the capability use \"%s\" to the whitelist in the application profile for the Pod \"%s\". You can use the following command: %s", capEvent.CapName, capEvent.GetPod(), rule.generatePatchCommand(capEvent, ap)),
			Severity:       R0004UnexpectedCapabilityUsedRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: capEvent.Comm,
				Gid:  capEvent.Gid,
				PID:  capEvent.Pid,
				Uid:  capEvent.Uid,
			},
			ContainerID: capEvent.Runtime.ContainerID,
		},
		TriggerEvent: capEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleID:          rule.ID(),
			RuleDescription: fmt.Sprintf("Unexpected capability used (capability %s used in syscall %s) in: %s", capEvent.CapName, capEvent.Syscall, capEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{},
	}

	return &ruleFailure
}

func (rule *R0004UnexpectedCapabilityUsed) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0004UnexpectedCapabilityUsedRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
