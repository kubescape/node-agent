package ruleengine

import (
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"

	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R1002ID                       = "R1002"
	R1002LoadKernelModuleRuleName = "Kernel Module Load"
)

var R1002LoadKernelModuleRuleDescriptor = RuleDescriptor{
	ID:          R1002ID,
	Name:        R1002LoadKernelModuleRuleName,
	Description: "Detecting Kernel Module Load.",
	Tags:        []string{"syscall", "kernel", "module", "load"},
	Priority:    RulePriorityCritical,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SyscallEventType,
		},
		NeedApplicationProfile: false,
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
	return R1002LoadKernelModuleRuleName
}
func (rule *R1002LoadKernelModule) ID() string {
	return R1002ID
}
func (rule *R1002LoadKernelModule) DeleteRule() {
}

func (rule *R1002LoadKernelModule) ProcessEvent(eventType utils.EventType, event interface{}, ap *v1beta1.ApplicationProfile, k8sProvider ruleengine.K8sObjectProvider) ruleengine.RuleFailure {
	if eventType != utils.SyscallEventType && eventType != utils.CapabilitiesEventType {
		return nil
	}

	syscallEvent, ok := event.(*tracercapabilitiestype.Event)
	if !ok {
		return nil
	}

	if syscallEvent.Syscall == "init_module" {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			Err:              "Kernel Module Load",
			FailureEvent:     utils.CapabilitiesToGeneralEvent(syscallEvent),
			FixSuggestionMsg: "If this is a legitimate action, please add consider removing this workload from the binding of this rule",
			RulePriority:     R1002LoadKernelModuleRuleDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R1002LoadKernelModule) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             []utils.EventType{utils.SyscallEventType},
		NeedApplicationProfile: false,
	}
}
