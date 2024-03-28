package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"slices"

	ruleenginetypes "node-agent/pkg/ruleengine/types"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R0003ID   = "R0003"
	R0003Name = "Unexpected system call"
)

var R0003UnexpectedSystemCallRuleDescriptor = RuleDescriptor{
	ID:          R0003ID,
	Name:        R0003Name,
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
	return R0003Name
}

func (rule *R0003UnexpectedSystemCall) ID() string {
	return R0003ID
}

func (rule *R0003UnexpectedSystemCall) DeleteRule() {
}

func (rule *R0003UnexpectedSystemCall) generatePatchCommand(unexpectedSyscall string, aa *v1beta1.ApplicationActivity) string {
	baseTemplate := "kubectl patch applicationactivity %s -n %s --type merge --patch '{\"spec\":{\"syscalls\":[\"%s\"]}}'"
	return fmt.Sprintf(baseTemplate, aa.GetName(), aa.GetNamespace(), unexpectedSyscall)
}

func (rule *R0003UnexpectedSystemCall) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*ruleenginetypes.SyscallEvent)
	if !ok {
		return nil
	}

	aa := objCache.ApplicationActivityCache().GetApplicationActivity(syscallEvent.GetNamespace(), syscallEvent.GetPod())
	if aa == nil {
		return nil
	}

	// If the syscall is whitelisted, return nil
	for _, syscall := range aa.Spec.Syscalls {
		if syscall == syscallEvent.SyscallName {
			return nil
		}
	}

	// We have already alerted for this syscall
	if slices.Contains(rule.listOfAlertedSyscalls, syscallEvent.SyscallName) {
		return nil
	}

	return &GenericRuleFailure{
		RuleName:         rule.Name(),
		RuleID:           rule.ID(),
		Err:              "Unexpected system call: " + syscallEvent.SyscallName,
		FixSuggestionMsg: fmt.Sprintf("If this is a valid behavior, please add the system call \"%s\" to the whitelist in the application profile for the Pod \"%s\". You can use the following command: %s", syscallEvent.SyscallName, syscallEvent.GetPod(), rule.generatePatchCommand(syscallEvent.SyscallName, aa)),
		FailureEvent:     utils.SyscallToGeneralEvent(syscallEvent),
		RulePriority:     R0003UnexpectedSystemCallRuleDescriptor.Priority,
	}
}

func (rule *R0003UnexpectedSystemCall) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             R0003UnexpectedSystemCallRuleDescriptor.Requirements.RequiredEventTypes(),
		NeedApplicationProfile: true,
	}
}
