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
	R1002ID   = "R1002"
	R1002Name = "Kernel Module Load"
)

var R1002LoadKernelModuleRuleDescriptor = ruleengine.RuleDescriptor{
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
	alerted bool
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

func (rule *R1002LoadKernelModule) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if rule.alerted {
		return nil
	}

	if eventType != utils.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*ruleenginetypes.SyscallEvent)
	if !ok {
		return nil
	}

	if syscallEvent.SyscallName == "init_module" || syscallEvent.SyscallName == "finit_module" {
		rule.alerted = true
		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				UniqueID:    HashStringToMD5(syscallEvent.SyscallName),
				AlertName:   rule.Name(),
				InfectedPID: syscallEvent.Pid,
				Severity:    R1002LoadKernelModuleRuleDescriptor.Priority,
				ProfileMetadata: &apitypes.ProfileMetadata{
					IsProfileDependent: false,
				},
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
				RuleDescription: fmt.Sprintf("Kernel module load syscall (%s) was called", syscallEvent.SyscallName),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName:   syscallEvent.GetPod(),
				PodLabels: syscallEvent.K8s.PodLabels,
			},
			RuleID: rule.ID(),
		}

		return &ruleFailure
	}

	return nil
}

func (rule *R1002LoadKernelModule) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1002LoadKernelModuleRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
