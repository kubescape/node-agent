package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"

	tracersyscallstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R0009ID       = "R0009"
	R0009Name     = "eBPF Program Load"
	BPF_PROG_LOAD = 5
)

var R0009EbpfProgramLoadRuleDescriptor = RuleDescriptor{
	ID:          R0009ID,
	Name:        R0009Name,
	Description: "Detecting eBPF program load.",
	Tags:        []string{"syscall", "ebpf"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SyscallEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0009EbpfProgramLoad()
	},
}

var _ ruleengine.RuleEvaluator = (*R0009EbpfProgramLoad)(nil)

type R0009EbpfProgramLoad struct {
	BaseRule
}

func CreateRuleR0009EbpfProgramLoad() *R0009EbpfProgramLoad {
	return &R0009EbpfProgramLoad{}
}

func (rule *R0009EbpfProgramLoad) Name() string {
	return R0009Name
}

func (rule *R0009EbpfProgramLoad) ID() string {
	return R0009ID
}
func (rule *R0009EbpfProgramLoad) DeleteRule() {
}

func (rule *R0009EbpfProgramLoad) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*tracersyscallstype.Event)
	if !ok {
		return nil
	}

	if syscallEvent.Syscall == "bpf" && syscallEvent.Parameters[0].Name == "cmd" && syscallEvent.Parameters[0].Value == fmt.Sprintf("%d", BPF_PROG_LOAD) {
		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:      rule.Name(),
				InfectedPID:    syscallEvent.Pid,
				FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
				Severity:       R0009EbpfProgramLoadRuleDescriptor.Priority,
			},
			RuntimeProcessDetails: apitypes.ProcessTree{
				ProcessTree: apitypes.Process{
					Comm: syscallEvent.Comm,
					PID:  syscallEvent.Pid,
				},
				ContainerID: syscallEvent.Runtime.ContainerID,
			},
			TriggerEvent: syscallEvent.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleID:          rule.ID(),
				RuleDescription: fmt.Sprintf("bpf system call executed in %s", syscallEvent.GetContainer()),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName: syscallEvent.GetPod(),
			},
		}

		return &ruleFailure
	}

	return nil
}

func (rule *R0009EbpfProgramLoad) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0009EbpfProgramLoadRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}