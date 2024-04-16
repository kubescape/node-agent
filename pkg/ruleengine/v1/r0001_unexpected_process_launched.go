package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"slices"
	"strings"

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
}

func (rule *R0001UnexpectedProcessLaunched) Name() string {
	return R0001Name
}
func (rule *R0001UnexpectedProcessLaunched) ID() string {
	return R0001ID
}

func CreateRuleR0001UnexpectedProcessLaunched() *R0001UnexpectedProcessLaunched {
	return &R0001UnexpectedProcessLaunched{}
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

	ap := objectCache.ApplicationProfileCache().GetApplicationProfile(execEvent.GetNamespace(), execEvent.GetPod())
	if ap == nil {
		return nil
	}

	appProfileExecList, err := getContainerFromApplicationProfile(ap, execEvent.GetContainer())
	if err != nil {
		return nil
	}

	for _, execCall := range appProfileExecList.Execs {
		if execCall.Path == execPath && slices.Compare(execCall.Args, execEvent.Args) == 0 {
			return nil
		}
	}

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
				UpperLayer: execEvent.UpperLayer,
				PPID:       execEvent.Ppid,
				Pcomm:      execEvent.Pcomm,
				Cwd:        execEvent.Cwd,
				Hardlink:   execEvent.ExePath,
				Cmdline:    fmt.Sprintf("%s %s", execPath, strings.Join(execEvent.Args, " ")),
			},
			ContainerID: execEvent.Runtime.ContainerID,
		},
		TriggerEvent: execEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleID:          rule.ID(),
			RuleDescription: fmt.Sprintf("Unexpected process launched: %s in: %s", execPath, execEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName: execEvent.GetPod(),
		},
	}

	return &ruleFailure
}

func (rule *R0001UnexpectedProcessLaunched) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0001UnexpectedProcessLaunchedRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
