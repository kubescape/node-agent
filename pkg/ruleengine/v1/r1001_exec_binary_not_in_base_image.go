package ruleengine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R1001ID   = "R1001"
	R1001Name = "Exec Binary Not In Base Image"
)

var R1001ExecBinaryNotInBaseImageRuleDescriptor = ruleengine.RuleDescriptor{
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

func (rule *R1001ExecBinaryNotInBaseImage) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{}) {
	if eventType != utils.ExecveEventType {
		return false, nil
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return false, nil
	}

	if execEvent.UpperLayer || execEvent.PupperLayer {
		return true, execEvent
	}

	return false, nil
}

func (rule *R1001ExecBinaryNotInBaseImage) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (bool, interface{}, error) {
	ok, execEvent := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !ok {
		return false, nil, nil
	}

	// Check if the event is expected, if so return nil
	whiteListed, err := IsExecEventInProfile(execEvent.(*events.ExecEvent), objCache, false)
	if whiteListed {
		return false, nil, nil
	} else if err != nil && !errors.Is(err, ProfileNotFound) {
		return false, nil, err
	}

	return true, nil, nil
}

func (rule *R1001ExecBinaryNotInBaseImage) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	execEvent, _ := event.(*events.ExecEvent)
	upperLayer := true

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s%s", execEvent.Comm, execEvent.ExePath, execEvent.Pcomm)),
			AlertName:   rule.Name(),
			InfectedPID: execEvent.Pid,
			Severity:    R1001ExecBinaryNotInBaseImageRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm:       execEvent.Comm,
				Gid:        &execEvent.Gid,
				PID:        execEvent.Pid,
				Uid:        &execEvent.Uid,
				UpperLayer: &upperLayer,
				PPID:       execEvent.Ppid,
				Pcomm:      execEvent.Pcomm,
				Cwd:        execEvent.Cwd,
				Hardlink:   execEvent.ExePath,
				Path:       GetExecFullPathFromEvent(execEvent),
				Cmdline:    fmt.Sprintf("%s %s", GetExecPathFromEvent(execEvent), strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
			},
			ContainerID: execEvent.Runtime.ContainerID,
		},
		TriggerEvent: execEvent.Event.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Process (%s) was executed and is not part of the image", execEvent.Comm),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   execEvent.GetPod(),
			PodLabels: execEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  execEvent.GetExtra(),
	}
}

func (rule *R1001ExecBinaryNotInBaseImage) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1001ExecBinaryNotInBaseImageRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Optional,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
