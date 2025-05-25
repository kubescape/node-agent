package ruleengine

import (
	"fmt"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
)

const (
	R0003ID   = "R0003"
	R0003Name = "Unexpected system call"
)

var R0003UnexpectedSystemCallRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R0003ID,
	Name:        R0003Name,
	Description: "Detecting unexpected system calls that are not whitelisted by application profile.",
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
	listOfAlertedSyscalls mapset.Set[string]
}

func CreateRuleR0003UnexpectedSystemCall() *R0003UnexpectedSystemCall {
	return &R0003UnexpectedSystemCall{
		listOfAlertedSyscalls: mapset.NewSet[string](),
	}
}

func (rule *R0003UnexpectedSystemCall) Name() string {
	return R0003Name
}

func (rule *R0003UnexpectedSystemCall) ID() string {
	return R0003ID
}

func (rule *R0003UnexpectedSystemCall) DeleteRule() {
}

func (rule *R0003UnexpectedSystemCall) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.SyscallEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	syscallEvent, ok := event.(*ruleenginetypes.SyscallEvent)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	// We have already alerted for this syscall
	if rule.listOfAlertedSyscalls.ContainsOne(syscallEvent.SyscallName) {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	return ruleengine.DetectionResult{IsFailure: true, Payload: syscallEvent}
}

func (rule *R0003UnexpectedSystemCall) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return detectionResult, nil
	}

	syscallEventTyped, _ := event.(*ruleenginetypes.SyscallEvent)
	ap, err := GetApplicationProfile(syscallEventTyped.Runtime.ContainerID, objCache)
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	container, err := GetContainerFromApplicationProfile(ap, syscallEventTyped.GetContainer())
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	// If the syscall is whitelisted, return nil
	for _, syscall := range container.Syscalls {
		if syscall == syscallEventTyped.SyscallName {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
		}
	}

	return ruleengine.DetectionResult{IsFailure: true, Payload: nil}, nil
}

func (rule *R0003UnexpectedSystemCall) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	syscallEvent, _ := event.(*ruleenginetypes.SyscallEvent)

	rule.listOfAlertedSyscalls.Add(syscallEvent.SyscallName)

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(syscallEvent.SyscallName),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"syscall": syscallEvent.SyscallName,
			},
			InfectedPID: syscallEvent.Pid,
			Severity:    R0003UnexpectedSystemCallRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				PID: syscallEvent.Pid,
			},
			ContainerID: syscallEvent.Runtime.ContainerID,
		},
		TriggerEvent: syscallEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Unexpected system call: %s", syscallEvent.SyscallName),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName: syscallEvent.GetPod(),
		},
		RuleID: rule.ID(),
	}
}

func (rule *R0003UnexpectedSystemCall) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0003UnexpectedSystemCallRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Required,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
