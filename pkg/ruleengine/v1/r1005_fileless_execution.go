package ruleengine

import (
	"fmt"
	"path/filepath"
	"strings"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R1005ID   = "R1005"
	R1005Name = "Fileless Execution"
)

var R1005FilelessExecutionRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R1005ID,
	Name:        R1005Name,
	Description: "Detecting Fileless Execution",
	Tags:        []string{"fileless", "execution"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.ExecveEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1005FilelessExecution()
	},
}

var _ ruleengine.RuleEvaluator = (*R1005FilelessExecution)(nil)

type R1005FilelessExecution struct {
	BaseRule
}

func CreateRuleR1005FilelessExecution() *R1005FilelessExecution {
	return &R1005FilelessExecution{}
}

func (rule *R1005FilelessExecution) Name() string {
	return R1005Name
}

func (rule *R1005FilelessExecution) ID() string {
	return R1005ID
}
func (rule *R1005FilelessExecution) DeleteRule() {
}

func (rule *R1005FilelessExecution) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, _ objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType == utils.ExecveEventType {
		return rule.handleExecveEvent(event.(*events.ExecEvent))
	}

	return nil
}

func (rule *R1005FilelessExecution) handleExecveEvent(execEvent *events.ExecEvent) ruleengine.RuleFailure {
	execFullPath := getExecFullPathFromEvent(execEvent)
	execPathDir := filepath.Dir(execFullPath)

	// Check for any /proc/*/fd/* or /proc/self/fd/* patterns
	// This covers both /proc/self/fd and /proc/<pid>/fd paths
	isProcFd := func(path string) bool {
		if strings.HasPrefix(path, "/proc/self/fd") {
			return true
		}
		// Match pattern like /proc/1/fd/7
		parts := strings.Split(path, "/")
		if len(parts) >= 4 &&
			parts[1] == "proc" &&
			parts[3] == "fd" {
			return true
		}
		return false
	}

	if isProcFd(execPathDir) || isProcFd(execEvent.Cwd) || isProcFd(execEvent.ExePath) {
		upperLayer := execEvent.UpperLayer || execEvent.PupperLayer
		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:   rule.Name(),
				InfectedPID: execEvent.Pid,
				Arguments: map[string]interface{}{
					"hardlink": execEvent.ExePath,
				},
				Severity: R1005FilelessExecutionRuleDescriptor.Priority,
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
					Path:       execFullPath,
					Cmdline:    fmt.Sprintf("%s %s", getExecPathFromEvent(execEvent), strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
				},
				ContainerID: execEvent.Runtime.ContainerID,
			},
			TriggerEvent: execEvent.Event.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleDescription: fmt.Sprintf("Fileless execution detected: exec call \"%s\" is from a malicious source \"/proc/*/fd\"", execPathDir),
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

	return nil
}

func (rule *R1005FilelessExecution) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1005FilelessExecutionRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
