package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"slices"

	ruleenginetypes "node-agent/pkg/ruleengine/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
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
	Priority:    RulePriorityLow,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SyscallEventType,
		},
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

func (rule *R0003UnexpectedSystemCall) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*ruleenginetypes.SyscallEvent)
	if !ok {
		return nil
	}

	ap := objCache.ApplicationProfileCache().GetApplicationProfile(syscallEvent.Runtime.ContainerID)
	if ap == nil {
		return nil
	}

	container, err := getContainerFromApplicationProfile(ap, syscallEvent.GetContainer())
	if err != nil {
		return nil
	}

	// If the syscall is whitelisted, return nil
	for _, syscall := range container.Syscalls {
		if syscall == syscallEvent.SyscallName {
			return nil
		}
	}

	// We have already alerted for this syscall
	if slices.Contains(rule.listOfAlertedSyscalls, syscallEvent.SyscallName) {
		return nil
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      rule.Name(),
			InfectedPID:    syscallEvent.Pid,
			FixSuggestions: fmt.Sprintf("If this is a valid behavior, please add the system call \"%s\" to the whitelist in the application profile for the Pod \"%s\".", syscallEvent.SyscallName, syscallEvent.GetPod()),
			Severity:       R0003UnexpectedSystemCallRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				PID: syscallEvent.Pid,
			},
			ContainerID: syscallEvent.Runtime.ContainerID,
		},
		TriggerEvent: syscallEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleID:          rule.ID(),
			RuleDescription: fmt.Sprintf("Unexpected system call: %s in: %s", syscallEvent.SyscallName, syscallEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{},
	}

	return &ruleFailure
}

func (rule *R0003UnexpectedSystemCall) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0003UnexpectedSystemCallRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
