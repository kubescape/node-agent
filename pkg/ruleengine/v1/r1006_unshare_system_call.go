package ruleengine

import (
	"fmt"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R1006ID   = "R1006"
	R1006Name = "Unshare System Call usage"
)

var R1006UnshareSyscallRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R1006ID,
	Name:        R1006Name,
	Description: "Detecting Unshare System Call usage, which can be used to escape container.",
	Tags:        []string{"syscall", "escape", "unshare"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SyscallEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1006UnshareSyscall()
	},
}

var _ ruleengine.RuleEvaluator = (*R1006UnshareSyscall)(nil)

type R1006UnshareSyscall struct {
	BaseRule
	alreadyNotified bool
}

func CreateRuleR1006UnshareSyscall() *R1006UnshareSyscall {
	return &R1006UnshareSyscall{alreadyNotified: false}
}

func (rule *R1006UnshareSyscall) Name() string {
	return R1006Name
}

func (rule *R1006UnshareSyscall) ID() string {
	return R1006ID
}
func (rule *R1006UnshareSyscall) DeleteRule() {
}

func (rule *R1006UnshareSyscall) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
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

	if syscallEvent.SyscallName == "unshare" {
		return ruleengine.DetectionResult{IsFailure: true, Payload: syscallEvent}
	}

	return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
}

func (rule *R1006UnshareSyscall) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return detectionResult, nil
	}

	// This rule doesn't need profile evaluation since it's based on direct detection
	return detectionResult, nil
}

func (rule *R1006UnshareSyscall) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	syscallEvent, _ := event.(*ruleenginetypes.SyscallEvent)
	rule.alreadyNotified = true

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(syscallEvent.SyscallName),
			AlertName:   rule.Name(),
			InfectedPID: syscallEvent.Pid,
			Severity:    R1006UnshareSyscallRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: syscallEvent.Comm,
				Gid:  &syscallEvent.Gid,
				PID:  syscallEvent.Pid,
				Uid:  &syscallEvent.Uid,
			},
			ContainerID: syscallEvent.Runtime.ContainerID,
		},
		TriggerEvent: syscallEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("unshare system call executed in %s", syscallEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   syscallEvent.GetPod(),
			PodLabels: syscallEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}
}

func (rule *R1006UnshareSyscall) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1006UnshareSyscallRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileType:       apitypes.ApplicationProfile,
			ProfileDependency: apitypes.NotRequired,
		},
	}
}
