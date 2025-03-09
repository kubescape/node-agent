package ruleengine

import (
	"fmt"
	"slices"
	"strings"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
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

func (rule *R0001UnexpectedProcessLaunched) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objectCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return nil
	}

	execPath := GetExecPathFromEvent(execEvent)

	ap := objectCache.ApplicationProfileCache().GetApplicationProfile(execEvent.Runtime.ContainerID)
	if ap == nil {
		return nil
	}

	appProfileExecList, err := GetContainerFromApplicationProfile(ap, execEvent.GetContainer())
	if err != nil {
		return nil
	}

	for _, execCall := range appProfileExecList.Execs {
		if execCall.Path == execPath {
			// if enforceArgs is set to true, we need to compare the arguments as well
			// if not set, we only compare the path
			if !rule.enforceArgs || slices.Compare(execCall.Args, execEvent.Args) == 0 {
				return nil
			}
		}
	}

	// If the parent process  is in the upper layer, the child process is also in the upper layer.
	upperLayer := execEvent.UpperLayer || execEvent.PupperLayer

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
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

	return &ruleFailure
}

func (rule *R0001UnexpectedProcessLaunched) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0001UnexpectedProcessLaunchedRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
