package ruleengine

import (
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/ruleengine/objectcache"
	"node-agent/pkg/utils"

	ruleenginetypes "node-agent/pkg/ruleengine/types"
)

const (
	R1002ID   = "R1002"
	R1002Name = "Kernel Module Load"
)

var R1002LoadKernelModuleRuleDescriptor = RuleDescriptor{
	ID:          R1002ID,
	Name:        R1002Name,
	Description: "Detecting Kernel Module Load.",
	Tags:        []string{"syscall", "kernel", "module", "load"},
	Priority:    RulePriorityCritical,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SyscallEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1002LoadKernelModule()
	},
}
var _ ruleengine.RuleEvaluator = (*R1002LoadKernelModule)(nil)

type R1002LoadKernelModule struct {
	BaseRule
}

func CreateRuleR1002LoadKernelModule() *R1002LoadKernelModule {
	return &R1002LoadKernelModule{}
}

func (rule *R1002LoadKernelModule) Name() string {
	return R1002Name
}
func (rule *R1002LoadKernelModule) ID() string {
	return R1002ID
}
func (rule *R1002LoadKernelModule) DeleteRule() {
}

func (rule *R1002LoadKernelModule) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*ruleenginetypes.SyscallEvent)
	if !ok {
		return nil
	}

	if syscallEvent.SyscallName == "init_module" {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			ContainerId:      syscallEvent.Runtime.ContainerID,
			Err:              "Kernel Module Load",
			FailureEvent:     utils.SyscallToGeneralEvent(syscallEvent),
			FixSuggestionMsg: "If this is a legitimate action, please add consider removing this workload from the binding of this rule",
			RulePriority:     R1002LoadKernelModuleRuleDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R1002LoadKernelModule) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1002LoadKernelModuleRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
