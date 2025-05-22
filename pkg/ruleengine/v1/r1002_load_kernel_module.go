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

func (rule *R1002LoadKernelModule) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{}) {
	if rule.alerted {
		return false, nil
	}

	if eventType != utils.SyscallEventType {
		return false, nil
	}

	syscallEvent, ok := event.(*ruleenginetypes.SyscallEvent)
	if !ok {
		return false, nil
	}

	if syscallEvent.SyscallName == "init_module" || syscallEvent.SyscallName == "finit_module" {
		return true, syscallEvent
	}

	return false, nil
}

func (rule *R1002LoadKernelModule) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (bool, interface{}, error) {
	// First do basic evaluation
	ok, _ := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !ok {
		return false, nil, nil
	}

	// This rule doesn't need profile evaluation since it's based on direct detection
	return true, nil, nil
}

func (rule *R1002LoadKernelModule) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload interface{}) ruleengine.RuleFailure {
	syscallEvent, _ := event.(*ruleenginetypes.SyscallEvent)
	rule.alerted = true

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(syscallEvent.SyscallName),
			AlertName:   rule.Name(),
			InfectedPID: syscallEvent.Pid,
			Severity:    R1002LoadKernelModuleRuleDescriptor.Priority,
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
}

func (rule *R1002LoadKernelModule) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1002LoadKernelModuleRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.NotRequired,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
