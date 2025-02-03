package ruleengine

import (
	"fmt"

	traceriouringtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/ruleengine/v1/helpers/iouring"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R1026ID   = "R1026"
	R1026Name = "Unexpected io_uring Operation Detected"
)

var R1026UnexpectedIouringOperationRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R1026ID,
	Name:        R1026Name,
	Description: "Detecting unexpected io_uring operations.",
	Tags:        []string{"syscalls", "io_uring"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.IoUringEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1026UnexpectedIouringOperation()
	},
}

var _ ruleengine.RuleEvaluator = (*R1026UnexpectedIouringOperation)(nil)

type R1026UnexpectedIouringOperation struct {
	BaseRule
}

func CreateRuleR1026UnexpectedIouringOperation() *R1026UnexpectedIouringOperation {
	return &R1026UnexpectedIouringOperation{}
}

func (rule *R1026UnexpectedIouringOperation) SetParameters(parameters map[string]interface{}) {
}

func (rule *R1026UnexpectedIouringOperation) Name() string {
	return R1026Name
}

func (rule *R1026UnexpectedIouringOperation) ID() string {
	return R1026ID
}

func (rule *R1026UnexpectedIouringOperation) DeleteRule() {
}

func (rule *R1026UnexpectedIouringOperation) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if !rule.EvaluateRule(eventType, event, objCache.K8sObjectCache()) {
		return nil
	}

	iouringEvent, ok := event.(*traceriouringtype.Event)
	if !ok {
		return nil
	}

	if allowed, err := IsAllowed(&iouringEvent.Event, objCache, iouringEvent.Identifier, R1026ID); err != nil {
		return nil
	} else if allowed {
		return nil
	}

	ok, name := iouring.GetOpcodeName(iouringEvent.Opcode)
	if !ok {
		return nil
	}

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"opcode":    iouringEvent.Opcode,
				"flags":     iouringEvent.Flags,
				"userData":  iouringEvent.UserData,
				"opertaion": name,
			},
			InfectedPID: iouringEvent.Pid,
			Severity:    R1026UnexpectedIouringOperationRuleDescriptor.Priority,
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
			RuleDescription: fmt.Sprintf("Unexpected io_uring operation detected: %s (opcode=%d) flags=0x%x in %s",
				name, iouringEvent.Opcode, iouringEvent.Flags, iouringEvent.Comm),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   iouringEvent.GetPod(),
			PodLabels: iouringEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}

}

func (rule *R1026UnexpectedIouringOperation) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, _ objectcache.K8sObjectCache) bool {
	if eventType != utils.IoUringEventType {
		return false
	}

	iouringEvent, ok := event.(*traceriouringtype.Event)
	if !ok {
		return ok
	}

	ok, _ = iouring.GetOpcodeName(iouringEvent.Opcode)
	return ok
}

func (rule *R1026UnexpectedIouringOperation) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1026UnexpectedIouringOperationRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
