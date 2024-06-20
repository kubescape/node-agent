package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"slices"

	ruleenginetypes "node-agent/pkg/ruleengine/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R0009ID   = "R0009"
	R0009Name = "eBPF Program Load"
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
	alreadyNotified bool
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

	ap := objCache.ApplicationProfileCache().GetApplicationProfile(syscallEvent.Runtime.ContainerID)
	if ap == nil {
		return nil
	}

	appProfileSyscallList, err := getContainerFromApplicationProfile(ap, syscallEvent.GetContainer())
	if err != nil {
		return nil
	}

	// Check if the syscall is in the list of allowed syscalls
	if slices.Contains(appProfileSyscallList.Syscalls, syscallEvent.SyscallName) {
		return nil
	}

	if syscallEvent.SyscallName == "bpf" {
		rule.alreadyNotified = true
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
				RuleDescription: fmt.Sprintf("bpf system call executed in %s", syscallEvent.GetContainer()),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName: syscallEvent.GetPod(),
			},
			RuleID: rule.ID(),
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
