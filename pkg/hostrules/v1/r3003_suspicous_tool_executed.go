package hostrules

import (
	"fmt"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	R3003ID   = "R3003"
	R3003Name = "Execution of suspicious security tool"
)

var R3003SuspiciousToolRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R3003ID,
	Name:        R3003Name,
	Description: "Detects execution of known suspicious security tools within containers",
	Tags:        []string{"security", "pentest", "tools"},
	Priority:    ruleengine.RulePriorityHigh,
	Requirements: &ruleenginev1.RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR3003SuspiciousTool()
	},
}

type R3003SuspiciousTool struct {
	ruleenginev1.BaseRule
}

func CreateRuleR3003SuspiciousTool() *R3003SuspiciousTool {
	return &R3003SuspiciousTool{}
}

func (rule *R3003SuspiciousTool) Name() string {
	return R3003Name
}

func (rule *R3003SuspiciousTool) ID() string {
	return R3003ID
}

func (rule *R3003SuspiciousTool) SetParameters(params map[string]interface{}) {
}

func (rule *R3003SuspiciousTool) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, _ objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return nil
	}

	execPath := ruleenginev1.GetExecPathFromEvent(execEvent)
	isSuspicious, severity, category := isSuspiciousTool(execPath)

	if !isSuspicious {
		return nil
	}

	ruleFailure := ruleenginev1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:   rule.Name(),
			InfectedPID: execEvent.Pid,
			Arguments: map[string]interface{}{
				"retval":   execEvent.Retval,
				"exec":     execEvent.ExePath,
				"args":     execEvent.Args,
				"category": category,
				"severity": severity,
			},
			Severity: severity,
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
			RuleDescription: fmt.Sprintf("Suspicious security tool executed: %s", execPath),
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

func (rule *R3003SuspiciousTool) Requirements() ruleengine.RuleSpec {
	return &ruleenginev1.RuleRequirements{
		EventTypes: R3003SuspiciousToolRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
