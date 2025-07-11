package ruleengine

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
)

const (
	R1004ID   = "R1004"
	R1004Name = "Exec from mount"
)

var R1004ExecFromMountRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R1004ID,
	Name:        R1004Name,
	Description: "Detecting exec calls from mounted paths.",
	Tags:        []string{"exec", "mount"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1004ExecFromMount()
	},
}

type R1004ExecFromMount struct {
	BaseRule
}

func CreateRuleR1004ExecFromMount() *R1004ExecFromMount {
	return &R1004ExecFromMount{}
}
func (rule *R1004ExecFromMount) Name() string {
	return R1004Name
}

func (rule *R1004ExecFromMount) ID() string {
	return R1004ID
}

func (rule *R1004ExecFromMount) DeleteRule() {
}

func (rule *R1004ExecFromMount) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.ExecveEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	mounts, err := GetContainerMountPaths(execEvent.GetNamespace(), execEvent.GetPod(), execEvent.GetContainer(), k8sObjCache)
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	for _, mount := range mounts {
		fullPath := GetExecFullPathFromEvent(execEvent)
		if rule.isPathContained(fullPath, mount) || rule.isPathContained(execEvent.ExePath, mount) {
			return ruleengine.DetectionResult{IsFailure: true, Payload: execEvent}
		}
	}

	return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
}

func (rule *R1004ExecFromMount) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return detectionResult, nil
	}

	execEventTyped, _ := event.(*events.ExecEvent)
	whiteListed, err := IsExecEventInProfile(execEventTyped, objCache, false)
	if whiteListed {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
	} else if err != nil && !errors.Is(err, ProfileNotFound) {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	return detectionResult, nil
}

func (rule *R1004ExecFromMount) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	execEvent, _ := event.(*events.ExecEvent)
	upperLayer := execEvent.UpperLayer || execEvent.PupperLayer

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s%s", execEvent.Comm, execEvent.ExePath, execEvent.Pcomm)),
			AlertName:   rule.Name(),
			InfectedPID: execEvent.Pid,
			Arguments: map[string]interface{}{
				"exec": execEvent.ExePath,
				"args": execEvent.Args,
			},
			Severity: R1004ExecFromMountRuleDescriptor.Priority,
			Identifiers: &common.Identifiers{
				Process: &common.ProcessEntity{
					Name:        execEvent.Comm,
					CommandLine: fmt.Sprintf("%s %s", GetExecFullPathFromEvent(execEvent), strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
				},
				File: &common.FileEntity{
					Name:      filepath.Base(GetExecFullPathFromEvent(execEvent)),
					Directory: filepath.Dir(GetExecFullPathFromEvent(execEvent)),
				},
			},
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
			RuleDescription: fmt.Sprintf("Process (%s) was executed from a mounted path", GetExecFullPathFromEvent(execEvent)),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   execEvent.GetPod(),
			PodLabels: execEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  execEvent.GetExtra(),
	}
}

func (rule *R1004ExecFromMount) isPathContained(targetpath, basepath string) bool {
	return strings.HasPrefix(targetpath, basepath)
}

func (rule *R1004ExecFromMount) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1004ExecFromMountRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Optional,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
