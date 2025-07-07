package ruleengine

import (
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	traceriouringtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/ruleengine/v1/helpers/iouring"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

const (
	R1030ID   = "R1030"
	R1030Name = "Unexpected io_uring Operation Detected"
)

var R1030UnexpectedIouringOperationRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R1030ID,
	Name:        R1030Name,
	Description: "Detects io_uring operations that were not recorded during the initial observation period, indicating potential unauthorized activity.",
	Tags:        []string{"syscalls", "io_uring"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.IoUringEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1030UnexpectedIouringOperation()
	},
	RulePolicySupport: true,
}

var _ ruleengine.RuleEvaluator = (*R1030UnexpectedIouringOperation)(nil)

type R1030UnexpectedIouringOperation struct {
	BaseRule
}

func CreateRuleR1030UnexpectedIouringOperation() *R1030UnexpectedIouringOperation {
	return &R1030UnexpectedIouringOperation{}
}

func (rule *R1030UnexpectedIouringOperation) SetParameters(parameters map[string]interface{}) {
}

func (rule *R1030UnexpectedIouringOperation) Name() string {
	return R1030Name
}

func (rule *R1030UnexpectedIouringOperation) ID() string {
	return R1030ID
}

func (rule *R1030UnexpectedIouringOperation) DeleteRule() {
}

func (rule *R1030UnexpectedIouringOperation) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, _ objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.IoUringEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	iouringEvent, ok := event.(*traceriouringtype.Event)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	ok, _ = iouring.GetOpcodeName(uint8(iouringEvent.Opcode))
	return ruleengine.DetectionResult{IsFailure: ok, Payload: nil}
}

func (rule *R1030UnexpectedIouringOperation) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return detectionResult, nil
	}

	iouringEvent, _ := event.(*traceriouringtype.Event)
	if allowed, err := IsAllowed(&iouringEvent.Event, objCache, iouringEvent.Comm, R1030ID); err != nil {
		logger.L().Error("RuleManager - failed to check if iouring event is allowed", helpers.Error(err))
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	} else if allowed {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
	}

	return detectionResult, nil
}

func (rule *R1030UnexpectedIouringOperation) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	iouringEvent, _ := event.(*traceriouringtype.Event)
	ok, name := iouring.GetOpcodeName(uint8(iouringEvent.Opcode))
	if !ok {
		return nil
	}

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(fmt.Sprintf("%s%s", name, iouringEvent.Comm)),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"opcode":    iouringEvent.Opcode,
				"flags":     iouringEvent.Flags,
				"operation": name,
			},
			InfectedPID:     iouringEvent.Pid,
			Severity:        R1030UnexpectedIouringOperationRuleDescriptor.Priority,
			ProfileMetadata: nil,
			Identifiers: &common.Identifiers{
				Process: &common.ProcessEntity{
					Name: iouringEvent.Comm,
				},
			},
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: iouringEvent.Comm,
				PID:  iouringEvent.Pid,
				Uid:  &iouringEvent.Uid,
				Gid:  &iouringEvent.Gid,
			},
			ContainerID: iouringEvent.Runtime.ContainerID,
		},
		TriggerEvent: iouringEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Unexpected io_uring operation detected: %s (opcode=%d) flags=0x%x in %s.",
				name, iouringEvent.Opcode, iouringEvent.Flags, iouringEvent.Comm),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   iouringEvent.GetPod(),
			PodLabels: iouringEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}
}

func (rule *R1030UnexpectedIouringOperation) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1030UnexpectedIouringOperationRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Required,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
