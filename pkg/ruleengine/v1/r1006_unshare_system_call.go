package ruleengine

import (
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/ruleengine/objectcache"
	"node-agent/pkg/utils"

	ruleenginetypes "node-agent/pkg/ruleengine/types"
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
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SyscallEventType,
		},
		NeedApplicationProfile: false,
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
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			Err:              "Unshare System Call usage",
			FailureEvent:     utils.SyscallToGeneralEvent(syscallEvent),
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
			RulePriority:     R1006UnshareSyscallRuleDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R1006UnshareSyscall) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             R1006UnshareSyscallRuleDescriptor.Requirements.RequiredEventTypes(),
		NeedApplicationProfile: false,
	}
}
