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

func (rule *R1005FilelessExecution) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{}) {
	if eventType != utils.ExecveEventType {
		return false, nil
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return false, nil
	}

	if !strings.Contains(execEvent.ExePath, "memfd") {
		return false, nil
	}

	execFullPath := GetExecFullPathFromEvent(execEvent)
	execPathDir := filepath.Dir(execFullPath)

	// Check for any /proc/*/fd/* or /proc/self/fd/* patterns
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
		return true, execEvent
	}

	return false, nil
}

func (rule *R1005FilelessExecution) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (bool, interface{}, error) {
	// First do basic evaluation
	ok, _ := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !ok {
		return false, nil, nil
	}

	// This rule doesn't need profile evaluation since it's based on direct detection
	return true, nil, nil
}

func (rule *R1005FilelessExecution) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	execEvent, _ := event.(*events.ExecEvent)
	execFullPath := GetExecFullPathFromEvent(execEvent)
	execPathDir := filepath.Dir(execFullPath)
	upperLayer := execEvent.UpperLayer || execEvent.PupperLayer

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s%s", execEvent.Comm, execEvent.ExePath, execEvent.Pcomm)),
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
				Cmdline:    fmt.Sprintf("%s %s", GetExecPathFromEvent(execEvent), strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
			},
			ContainerID: execEvent.Runtime.ContainerID,
		},
		TriggerEvent: execEvent.Event.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Fileless execution detected: exec call \"%s\" is from a malicious source %s", execPathDir, execEvent.ExePath),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   execEvent.GetPod(),
			PodLabels: execEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  execEvent.GetExtra(),
	}
}

func (rule *R1005FilelessExecution) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1005FilelessExecutionRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileType:       apitypes.ApplicationProfile,
			ProfileDependency: apitypes.NotRequired,
		},
	}
}
