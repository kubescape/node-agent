package ruleengine

import (
	"fmt"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"

	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R0004ID                               = "R0004"
	R0004UnexpectedCapabilityUsedRuleName = "Unexpected capability used"
)

var R0004UnexpectedCapabilityUsedRuleDescriptor = RuleDescriptor{
	ID:          R0004ID,
	Name:        R0004UnexpectedCapabilityUsedRuleName,
	Description: "Detecting unexpected capabilities that are not whitelisted by application profile. Every unexpected capability is identified in context of a syscall and will be alerted only once per container.",
	Tags:        []string{"capabilities", "whitelisted"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes:             []utils.EventType{utils.CapabilitiesEventType},
		NeedApplicationProfile: true,
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
	return R0004UnexpectedCapabilityUsedRuleName
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

func (rule *R0004UnexpectedCapabilityUsed) ProcessEvent(eventType utils.EventType, event interface{}, ap *v1beta1.ApplicationProfile, k8sProvider ruleengine.K8sObjectProvider) ruleengine.RuleFailure {
	if eventType != utils.CapabilitiesEventType {
		return nil
	}

	capEvent, ok := event.(*tracercapabilitiestype.Event)
	if !ok {
		return nil
	}

	if ap == nil {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod %s", capEvent.GetPod()),
			FailureEvent:     utils.CapabilitiesToGeneralEvent(capEvent),
			RulePriority:     R0004UnexpectedCapabilityUsedRuleDescriptor.Priority,
		}
	}

	appProfileCapabilitiesList, err := getContainerFromApplicationProfile(ap, capEvent.GetContainer())
	if err != nil {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod %s", capEvent.GetPod()),
			FailureEvent:     utils.CapabilitiesToGeneralEvent(capEvent),
			RulePriority:     R0004UnexpectedCapabilityUsedRuleDescriptor.Priority,
		}
	}

	for _, cap := range appProfileCapabilitiesList.Capabilities {
		if capEvent.CapName == cap {
			return nil
		}
	}

	return &GenericRuleFailure{
		RuleName:         rule.Name(),
		RuleID:           rule.ID(),
		Err:              fmt.Sprintf("Unexpected capability used (capability %s used in syscall %s)", capEvent.CapName, capEvent.Syscall),
		FixSuggestionMsg: fmt.Sprintf("If this is a valid behavior, please add the capability use \"%s\" to the whitelist in the application profile for the Pod \"%s\". You can use the following command: %s", capEvent.CapName, capEvent.GetPod(), rule.generatePatchCommand(capEvent, ap)),
		FailureEvent:     utils.CapabilitiesToGeneralEvent(capEvent),
		RulePriority:     R0004UnexpectedCapabilityUsedRuleDescriptor.Priority,
	}
}

func (rule *R0004UnexpectedCapabilityUsed) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             []utils.EventType{utils.CapabilitiesEventType},
		NeedApplicationProfile: true,
	}
}