package ruleengine

import (
	"fmt"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R1006ID   = "R1006"
	R1006Name = "Unshare System Call usage"
)

var R1006UnshareSyscallRuleDescriptor = RuleDescriptor{
	ID:          R1006ID,
	Name:        R1006Name,
	Description: "Detecting Unshare System Call usage, which can be used to escape container.",
	Tags:        []string{"syscall", "escape", "unshare"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SyscallEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1006UnshareSyscall()
	},
}

var _ ruleengine.RuleEvaluator = (*R1006UnshareSyscall)(nil)

type R1006UnshareSyscall struct {
	BaseRule
	alreadyNotified bool
}

func CreateRuleR1006UnshareSyscall() *R1006UnshareSyscall {
	return &R1006UnshareSyscall{alreadyNotified: false}
}

func (rule *R1006UnshareSyscall) Name() string {
	return R1006Name
}

func (rule *R1006UnshareSyscall) ID() string {
	return R1006ID
}
func (rule *R1006UnshareSyscall) DeleteRule() {
}

func (rule *R1006UnshareSyscall) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if rule.alreadyNotified {
		return nil
	}

	if eventType != utils.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*ruleenginetypes.SyscallEvent)
	if !ok {
		return nil
	}

	if syscallEvent.SyscallName == "unshare" {
		rule.alreadyNotified = true
		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:      rule.Name(),
				InfectedPID:    syscallEvent.Pid,
				FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
				Severity:       R1006UnshareSyscallRuleDescriptor.Priority,
			},
			RuntimeProcessDetails: apitypes.ProcessTree{
				ProcessTree: apitypes.Process{
					Comm: syscallEvent.Comm,
					Gid:  &syscallEvent.Gid,
					PID:  syscallEvent.Pid,
					Uid:  &syscallEvent.Uid,
				},
				ContainerID: syscallEvent.Runtime.ContainerID,
			},
			TriggerEvent: syscallEvent.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleID:          rule.ID(),
				RuleDescription: fmt.Sprintf("unshare system call executed in %s", syscallEvent.GetContainer()),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName: syscallEvent.GetPod(),
			},
		}

		return &ruleFailure
	}

	return nil
}

func (rule *R1006UnshareSyscall) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1006UnshareSyscallRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
