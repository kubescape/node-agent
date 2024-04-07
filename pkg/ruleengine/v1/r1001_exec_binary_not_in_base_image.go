package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

const (
	R1001ID   = "R1001"
	R1001Name = "Exec Binary Not In Base Image"
)

var R1001ExecBinaryNotInBaseImageRuleDescriptor = RuleDescriptor{
	ID:          R1001ID,
	Name:        R1001Name,
	Description: "Detecting exec calls of binaries that are not included in the base image",
	Tags:        []string{"exec", "malicious", "binary", "base image"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1001ExecBinaryNotInBaseImage()
	},
}
var _ ruleengine.RuleEvaluator = (*R1001ExecBinaryNotInBaseImage)(nil)

type R1001ExecBinaryNotInBaseImage struct {
	BaseRule
}

func CreateRuleR1001ExecBinaryNotInBaseImage() *R1001ExecBinaryNotInBaseImage {
	return &R1001ExecBinaryNotInBaseImage{}
}

func (rule *R1001ExecBinaryNotInBaseImage) Name() string {
	return R1001Name
}

func (rule *R1001ExecBinaryNotInBaseImage) ID() string {
	return R1001ID
}

func (rule *R1001ExecBinaryNotInBaseImage) DeleteRule() {
}

func (rule *R1001ExecBinaryNotInBaseImage) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracerexectype.Event)
	if !ok {
		return nil
	}

	if execEvent.UpperLayer {
		isPartOfImage := !execEvent.UpperLayer
		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:      rule.Name(),
				FixSuggestions: "If this is an expected behavior it is strongly suggested to include all executables in the container image. If this is not possible you can remove the rule binding to this workload.",
				Severity:       R1001ExecBinaryNotInBaseImageRuleDescriptor.Priority,
				IsPartOfImage:  &isPartOfImage,
				PPID:           &execEvent.Ppid,
				PPIDComm:       &execEvent.Pcomm,
			},
			RuntimeProcessDetails: apitypes.RuntimeAlertProcessDetails{
				Comm: execEvent.Comm,
				GID:  execEvent.Gid,
				PID:  execEvent.Pid,
				UID:  execEvent.Uid,
			},
			TriggerEvent: execEvent.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleID:          rule.ID(),
				RuleDescription: fmt.Sprintf("Process image \"%s\" binary is not from the container image \"%s\"", getExecPathFromEvent(execEvent), execEvent.GetContainerImageName()),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{},
		}

		enrichRuleFailure(execEvent.Event, execEvent.Pid, &ruleFailure)

		return &ruleFailure
	}

	return nil
}

func (rule *R1001ExecBinaryNotInBaseImage) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1001ExecBinaryNotInBaseImageRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
