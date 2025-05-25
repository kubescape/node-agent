package ruleengine

import (
	"fmt"
	"slices"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"
)

const (
	R0009ID   = "R0009"
	R0009Name = "eBPF Program Load"
)

var R0009EbpfProgramLoadRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R0009ID,
	Name:        R0009Name,
	Description: "Detecting eBPF program load.",
	Tags:        []string{"syscall", "ebpf"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SyscallEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0009EbpfProgramLoad()
	},
}

var _ ruleengine.RuleEvaluator = (*R0009EbpfProgramLoad)(nil)

type R0009EbpfProgramLoad struct {
	BaseRule
	alreadyNotified bool
}

func CreateRuleR0009EbpfProgramLoad() *R0009EbpfProgramLoad {
	return &R0009EbpfProgramLoad{}
}

func (rule *R0009EbpfProgramLoad) Name() string {
	return R0009Name
}

func (rule *R0009EbpfProgramLoad) ID() string {
	return R0009ID
}
func (rule *R0009EbpfProgramLoad) DeleteRule() {
}

func (rule *R0009EbpfProgramLoad) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if rule.alreadyNotified {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	if eventType != utils.SyscallEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	syscallEvent, ok := event.(*ruleenginetypes.SyscallEvent)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	if syscallEvent.SyscallName == "bpf" {
		return ruleengine.DetectionResult{IsFailure: true, Payload: syscallEvent}
	}

	return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
}

func (rule *R0009EbpfProgramLoad) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
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

	appProfileSyscallList, err := GetContainerFromApplicationProfile(ap, syscallEventTyped.GetContainer())
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	// Check if the syscall is in the list of allowed syscalls
	if slices.Contains(appProfileSyscallList.Syscalls, syscallEventTyped.SyscallName) {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
	}

	return detectionResult, nil
}

func (rule *R0009EbpfProgramLoad) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	syscallEvent, _ := event.(*ruleenginetypes.SyscallEvent)
	rule.alreadyNotified = true

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(fmt.Sprintf("%s%s", syscallEvent.Comm, syscallEvent.SyscallName)),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"syscall": syscallEvent.SyscallName,
			},
			InfectedPID: syscallEvent.Pid,
			Severity:    R0009EbpfProgramLoadRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: syscallEvent.Comm,
				PID:  syscallEvent.Pid,
			},
			ContainerID: syscallEvent.Runtime.ContainerID,
		},
		TriggerEvent: syscallEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("bpf system call executed in %s", syscallEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   syscallEvent.GetPod(),
			PodLabels: syscallEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}
}

func (rule *R0009EbpfProgramLoad) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0009EbpfProgramLoadRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Optional,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
