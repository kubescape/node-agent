package ruleengine

import (
	"encoding/json"
	"fmt"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/ruleengine/objectcache"
	"node-agent/pkg/utils"
	"strings"

	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R0003ID                           = "R0003"
	R0003UnexpectedSystemCallRuleName = "Unexpected system call"
)

var R0003UnexpectedSystemCallRuleDescriptor = RuleDescriptor{
	ID:          R0003ID,
	Name:        R0003UnexpectedSystemCallRuleName,
	Description: "Detecting unexpected system calls that are not whitelisted by application profile. Every unexpected system call will be alerted only once.",
	Tags:        []string{"syscall", "whitelisted"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SyscallEventType,
		},
		NeedApplicationProfile: true,
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0003UnexpectedSystemCall()
	},
}

var _ ruleengine.RuleEvaluator = (*R0003UnexpectedSystemCall)(nil)

type R0003UnexpectedSystemCall struct {
	BaseRule
	listOfAlertedSyscalls []string
}

func CreateRuleR0003UnexpectedSystemCall() *R0003UnexpectedSystemCall {
	return &R0003UnexpectedSystemCall{}
}

func (rule *R0003UnexpectedSystemCall) Name() string {
	return R0003UnexpectedSystemCallRuleName
}

func (rule *R0003UnexpectedSystemCall) ID() string {
	return R0003ID
}

func (rule *R0003UnexpectedSystemCall) DeleteRule() {
}

func (rule *R0003UnexpectedSystemCall) generatePatchCommand(event *tracercapabilitiestype.Event, unexpectedSyscalls []string, ap *v1beta1.ApplicationProfile) string {
	syscallList, err := json.Marshal(unexpectedSyscalls)
	if err != nil {
		return ""
	}
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"syscalls\": %s}]}}'"
	return fmt.Sprintf(baseTemplate, ap.GetName(), ap.GetNamespace(),
		event.GetContainer(), syscallList)
}

func (rule *R0003UnexpectedSystemCall) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.SyscallEventType && eventType != utils.CapabilitiesEventType {
		return nil
	}

	syscallEvent, ok := event.(*tracercapabilitiestype.Event)
	if !ok {
		return nil
	}

	ap := objCache.ApplicationProfileCache().GetApplicationProfile(syscallEvent.GetNamespace(), syscallEvent.GetPod())

	if ap == nil {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod %s", syscallEvent.GetPod()),
			FailureEvent:     utils.CapabilitiesToGeneralEvent(syscallEvent),
			RulePriority:     R0003UnexpectedSystemCallRuleDescriptor.Priority,
		}
	}

	appProfileSyscallList, err := getContainerFromApplicationProfile(ap, syscallEvent.GetContainer())
	if err != nil {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			Err:              "Application profile is missing (missing syscall list))",
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod %s", syscallEvent.GetPod()),
			FailureEvent:     utils.CapabilitiesToGeneralEvent(syscallEvent),
			RulePriority:     R0003UnexpectedSystemCallRuleDescriptor.Priority,
		}
	}

	unexpectedSyscalls := []string{}
	// Check in the appProfileSyscallList if the syscallEventName is there
	for _, syscall := range appProfileSyscallList.Syscalls {
		if syscall == syscallEvent.Syscall {
			// if syscall is already in the application profile, return nil
			return nil
		}

		// Check if the syscallEventName is in the listOfAlertedSyscalls
		for _, alertedSyscall := range rule.listOfAlertedSyscalls {
			if alertedSyscall == syscallEvent.Syscall {
				unexpectedSyscalls = append(unexpectedSyscalls, syscallEvent.Syscall)
			}
		}
	}

	if len(unexpectedSyscalls) > 0 {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			Err:              "Unexpected system calls: " + strings.Join(unexpectedSyscalls, ", "),
			FixSuggestionMsg: fmt.Sprintf("If this is a valid behavior, please add the system call(s) \"%s\" to the whitelist in the application profile for the Pod \"%s\". You can use the following command: %s", strings.Join(unexpectedSyscalls, ", "), syscallEvent.GetPod(), rule.generatePatchCommand(syscallEvent, unexpectedSyscalls, ap)),
			FailureEvent:     utils.CapabilitiesToGeneralEvent(syscallEvent),
			RulePriority:     R0003UnexpectedSystemCallRuleDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R0003UnexpectedSystemCall) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             []utils.EventType{utils.SyscallEventType},
		NeedApplicationProfile: true,
	}
}
