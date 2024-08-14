package ruleengine

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

const (
	R1005ID   = "R1005"
	R1005Name = "Fileless Execution"
)

var R1005FilelessExecutionRuleDescriptor = RuleDescriptor{
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

func (rule *R1005FilelessExecution) ProcessEvent(eventType utils.EventType, event interface{}, _ objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType == utils.ExecveEventType {
		return rule.handleExecveEvent(event.(*tracerexectype.Event))
	}

	return nil
}

func (rule *R1005FilelessExecution) handleExecveEvent(execEvent *tracerexectype.Event) ruleengine.RuleFailure {
	execFullPath := getExecFullPathFromEvent(execEvent)
	execPathDir := filepath.Dir(execFullPath)

	// /proc/self/fd/<n> is a classic way to hide malicious execs
	// (see ezuri packer for example)
	// Here it would be even more interesting to check if the fd
	// is memory mapped file

	if strings.HasPrefix(execPathDir, "/proc/self/fd") || strings.HasPrefix(execEvent.Cwd, "/proc/self/fd") || strings.HasPrefix(execEvent.ExePath, "/proc/self/fd") {
		upperLayer := execEvent.UpperLayer || execEvent.PupperLayer
		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:   rule.Name(),
				InfectedPID: execEvent.Pid,
				Arguments: map[string]interface{}{
					"hardlink": execEvent.ExePath,
				},
				FixSuggestions: "If this is a legitimate action, please add consider removing this workload from the binding of this rule.",
				Severity:       R1005FilelessExecutionRuleDescriptor.Priority,
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
					Cmdline:    fmt.Sprintf("%s %s", getExecPathFromEvent(execEvent), strings.Join(utils.GetExecArgsFromEvent(execEvent), " ")),
				},
				ContainerID: execEvent.Runtime.ContainerID,
			},
			TriggerEvent: execEvent.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleDescription: fmt.Sprintf("Fileless execution detected: exec call \"%s\" is from a malicious source \"%s\"", execPathDir, "/proc/self/fd"),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName: execEvent.GetPod(),
			},
			RuleID: rule.ID(),
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
