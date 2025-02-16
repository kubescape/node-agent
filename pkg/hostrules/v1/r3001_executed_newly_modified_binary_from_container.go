package hostrules

import (
	"fmt"
	"strings"
	"time"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R3001ID                = "R3001"
	R3001Name              = "Execution of newly modified binary from container"
	NewlyModifiedThreshold = 5 * time.Minute
)

var R3001UnexpectedProcessLaunchedRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R3001ID,
	Name:        R3001Name,
	Description: "Detects execution of newly modified binaries within containers",
	Tags:        []string{"exec", "whitelisted"},
	Priority:    ruleengine.RulePriorityMed,
	Requirements: &ruleenginev1.RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR3001UnexpectedProcessLaunched()
	},
}
var _ ruleengine.RuleEvaluator = (*R3001NewlyModifedBinaryProcessLaunched)(nil)

type R3001NewlyModifedBinaryProcessLaunched struct {
	ruleenginev1.BaseRule
	enforceArgs bool
}

func (rule *R3001NewlyModifedBinaryProcessLaunched) SetParameters(params map[string]interface{}) {

}

func (rule *R3001NewlyModifedBinaryProcessLaunched) Name() string {
	return R3001Name
}
func (rule *R3001NewlyModifedBinaryProcessLaunched) ID() string {
	return R3001ID
}

func CreateRuleR3001UnexpectedProcessLaunched() *R3001NewlyModifedBinaryProcessLaunched {
	return &R3001NewlyModifedBinaryProcessLaunched{enforceArgs: false}
}

func (rule *R3001NewlyModifedBinaryProcessLaunched) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, _ objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return nil
	}

	if execEvent.Runtime.ContainerID == "" {
		return nil
	}

	execPath := ruleenginev1.GetExecPathFromEvent(execEvent) // Is real path

	thresholdTime := time.Now().Add(-NewlyModifiedThreshold)

	if !isPathNewlyModified(execPath, thresholdTime) {
		return nil
	}

	ruleFailure := ruleenginev1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:   rule.Name(),
			InfectedPID: execEvent.Pid,
			Arguments: map[string]interface{}{
				"retval": execEvent.Retval,
				"exec":   execEvent.ExePath,
				"args":   execEvent.Args,
			},
			Severity: R3001UnexpectedProcessLaunchedRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm:     execEvent.Comm,
				Gid:      &execEvent.Gid,
				PID:      execEvent.Pid,
				Uid:      &execEvent.Uid,
				PPID:     execEvent.Ppid,
				Pcomm:    execEvent.Pcomm,
				Cwd:      execEvent.Cwd,
				Hardlink: execEvent.ExePath,
				Path:     execPath,
				Cmdline:  fmt.Sprintf("%s %s", execPath, strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
			},
			ContainerID: execEvent.Runtime.ContainerID,
		},
		TriggerEvent: execEvent.Event.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("A newly modified binary was executed: %s in container: %s", execPath, execEvent.GetContainer()),
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

func (rule *R3001NewlyModifedBinaryProcessLaunched) Requirements() ruleengine.RuleSpec {
	return &ruleenginev1.RuleRequirements{
		EventTypes: R3001UnexpectedProcessLaunchedRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
