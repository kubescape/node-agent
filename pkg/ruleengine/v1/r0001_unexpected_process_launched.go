package ruleengine

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R0001ID   = "R0001"
	R0001Name = "Unexpected process launched"
)

var R0001UnexpectedProcessLaunchedRuleDescriptor = RuleDescriptor{
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

func (rule *R0001UnexpectedProcessLaunched) generatePatchCommand(event *tracerexectype.Event, ap *v1beta1.ApplicationProfile) string {
	argList := "["
	for _, arg := range event.Args {
		argList += "\"" + arg + "\","
	}
	// remove the last comma
	if len(argList) > 1 {
		argList = argList[:len(argList)-1]
	}
	argList += "]"
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"execs\": [{\"path\": \"%s\", \"args\": %s}]}]}}'"
	return fmt.Sprintf(baseTemplate, ap.GetName(), ap.GetNamespace(),
		event.GetContainer(), getExecPathFromEvent(event), argList)
}

func (rule *R0001UnexpectedProcessLaunched) ProcessEvent(eventType utils.EventType, event interface{}, objectCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracerexectype.Event)
	if !ok {
		return nil
	}

	execPath := getExecPathFromEvent(execEvent)

	ap := objectCache.ApplicationProfileCache().GetApplicationProfile(execEvent.Runtime.ContainerID)
	if ap == nil {
		return nil
	}

	appProfileExecList, err := getContainerFromApplicationProfile(ap, execEvent.GetContainer())
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
			},
			FixSuggestions: fmt.Sprintf("If this is a valid behavior, please add the exec call \"%s\" to the whitelist in the application profile for the Pod \"%s\". You can use the following command: %s", execPath, execEvent.GetPod(), rule.generatePatchCommand(execEvent, ap)),
			Severity:       R0001UnexpectedProcessLaunchedRuleDescriptor.Priority,
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
				Path:       getExecFullPathFromEvent(execEvent),
				Cmdline:    fmt.Sprintf("%s %s", execPath, strings.Join(utils.GetExecArgsFromEvent(execEvent), " ")),
			},
			ContainerID: execEvent.Runtime.ContainerID,
		},
		TriggerEvent: execEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Unexpected process launched: %s in: %s", execPath, execEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   execEvent.GetPod(),
			PodLabels: execEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}

	return &ruleFailure
}

func (rule *R0001UnexpectedProcessLaunched) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0001UnexpectedProcessLaunchedRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
