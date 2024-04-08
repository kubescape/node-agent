package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"path/filepath"
	"strings"

	ruleenginetypes "node-agent/pkg/ruleengine/types"

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
	Tags:        []string{"syscall", "fileless", "execution"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SyscallEventType,
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
	alreadyNotified bool
}

func CreateRuleR1005FilelessExecution() *R1005FilelessExecution {
	return &R1005FilelessExecution{alreadyNotified: false}
}

func (rule *R1005FilelessExecution) Name() string {
	return R1005Name
}

func (rule *R1005FilelessExecution) ID() string {
	return R1005ID
}
func (rule *R1005FilelessExecution) DeleteRule() {
}

func (rule *R1005FilelessExecution) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType == utils.SyscallEventType {
		return rule.handleSyscallEvent(event.(*ruleenginetypes.SyscallEvent))
	} else if eventType == utils.ExecveEventType {
		return rule.handleExecveEvent(event.(*tracerexectype.Event))
	}

	return nil
}

func (rule *R1005FilelessExecution) handleSyscallEvent(syscallEvent *ruleenginetypes.SyscallEvent) ruleengine.RuleFailure {
	if rule.alreadyNotified {
		return nil
	}

	if syscallEvent.SyscallName == "memfd_create" {
		rule.alreadyNotified = true
		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:      rule.Name(),
				FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
				Severity:       R1005FilelessExecutionRuleDescriptor.Priority,
			},
			RuntimeProcessDetails: apitypes.RuntimeAlertProcessDetails{
				Comm: syscallEvent.Comm,
				GID:  syscallEvent.Gid,
				PID:  syscallEvent.Pid,
				UID:  syscallEvent.Uid,
			},
			TriggerEvent: syscallEvent.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleID:          rule.ID(),
				RuleDescription: "memfd_create syscall detected",
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{},
		}

		enrichRuleFailure(syscallEvent.Event, syscallEvent.Pid, &ruleFailure)

		return &ruleFailure
	}

	return nil
}

func (rule *R1005FilelessExecution) handleExecveEvent(execEvent *tracerexectype.Event) ruleengine.RuleFailure {
	execPath := getExecPathFromEvent(execEvent)
	if strings.HasPrefix(execPath, "./") || strings.HasPrefix(execPath, "../") {
		execPath = filepath.Join(execEvent.Cwd, execPath)
	} else if !strings.HasPrefix(execPath, "/") {
		execPath = "/" + execPath
	}
	execPath = filepath.Dir(execPath)

	if strings.HasPrefix(execPath, "/proc/self/fd") || strings.HasPrefix(execEvent.Cwd, "/proc/self/fd") {
		isPartOfImage := !execEvent.UpperLayer
		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:      rule.Name(),
				FixSuggestions: "If this is a legitimate action, please add consider removing this workload from the binding of this rule.",
				Severity:       R1005FilelessExecutionRuleDescriptor.Priority,
				IsPartOfImage:  &isPartOfImage,
				PPID:           &execEvent.Ppid,
				PPIDComm:       &execEvent.Pcomm,
			},
			RuntimeProcessDetails: apitypes.RuntimeAlertProcessDetails{
				Comm: execEvent.Comm,
				GID:  execEvent.Gid,
				PID:  execEvent.Pid,
				UID:  execEvent.Uid,
			},
			TriggerEvent: execEvent.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleID:          rule.ID(),
				RuleDescription: fmt.Sprintf("Fileless execution detected: exec call \"%s\" is from a malicious source \"%s\"", execPath, "/proc/self/fd"),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{},
		}

		enrichRuleFailure(execEvent.Event, execEvent.Pid, &ruleFailure)

		return &ruleFailure
	}

	return nil
}

func (rule *R1005FilelessExecution) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1005FilelessExecutionRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
