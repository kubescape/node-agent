package ruleengine

import (
	"fmt"
	"slices"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	R0001ID   = "R0001"
	R0001Name = "Unexpected process launched"
)

var R0001UnexpectedProcessLaunchedRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R0001ID,
	Name:        R0001Name,
	Description: "Detecting exec calls that are not whitelisted by application profile",
	Tags:        []string{"exec", "whitelisted"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0001UnexpectedProcessLaunched()
	},
}
var _ ruleengine.RuleEvaluator = (*R0001UnexpectedProcessLaunched)(nil)

type R0001UnexpectedProcessLaunched struct {
	BaseRule
	enforceArgs bool
}

func (rule *R0001UnexpectedProcessLaunched) SetParameters(params map[string]interface{}) {
	if enforceArgs, ok := params["enforceArgs"].(bool); ok {
		rule.enforceArgs = enforceArgs
	} else {
		rule.enforceArgs = false
	}
}

func (rule *R0001UnexpectedProcessLaunched) Name() string {
	return R0001Name
}
func (rule *R0001UnexpectedProcessLaunched) ID() string {
	return R0001ID
}

func CreateRuleR0001UnexpectedProcessLaunched() *R0001UnexpectedProcessLaunched {
	return &R0001UnexpectedProcessLaunched{enforceArgs: false}
}

func (rule *R0001UnexpectedProcessLaunched) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.ExecveEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	execPath := GetExecPathFromEvent(execEvent)
	return ruleengine.DetectionResult{IsFailure: true, Payload: execPath}
}

func (rule *R0001UnexpectedProcessLaunched) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return detectionResult, nil
	}

	execEvent, _ := event.(*events.ExecEvent)
	ap, err := GetApplicationProfile(execEvent.Runtime.ContainerID, objCache)
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	appProfileExecList, err := GetContainerFromApplicationProfile(ap, execEvent.GetContainer())
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	for _, execCall := range appProfileExecList.Execs {
		if execCall.Path == detectionResult.Payload {
			// if enforceArgs is set to true, we need to compare the arguments as well
			// if not set, we only compare the path
			if !rule.enforceArgs || slices.Compare(execCall.Args, execEvent.Args) == 0 {
				return ruleengine.DetectionResult{IsFailure: false, Payload: execCall.Path}, nil
			}
		}
	}

	return ruleengine.DetectionResult{IsFailure: true, Payload: nil}, nil
}

func (rule *R0001UnexpectedProcessLaunched) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	execEvent, _ := event.(*events.ExecEvent)
	execPath := GetExecPathFromEvent(execEvent)

	// If the parent process is in the upper layer, the child process is also in the upper layer.
	upperLayer := execEvent.UpperLayer || execEvent.PupperLayer

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s%s", execEvent.Comm, execEvent.ExePath, execEvent.Pcomm)),
			AlertName:   rule.Name(),
			InfectedPID: execEvent.Pid,
			Arguments: map[string]interface{}{
				"retval": execEvent.Retval,
				"exec":   execPath,
				"args":   execEvent.Args,
			},
			Severity: R0001UnexpectedProcessLaunchedRuleDescriptor.Priority,
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
				Cmdline:    fmt.Sprintf("%s %s", execPath, strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
			},
			ContainerID: execEvent.Runtime.ContainerID,
		},
		TriggerEvent: execEvent.Event.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Unexpected process launched: %s", execPath),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   execEvent.GetPod(),
			PodLabels: execEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  execEvent.GetExtra(),
	}
}

func (rule *R0001UnexpectedProcessLaunched) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0001UnexpectedProcessLaunchedRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Required,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
