package ruleengine

import (
	"fmt"
	"path/filepath"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"

	tracerptracetype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer/types"
)

const (
	R1015ID   = "R1015"
	R1015Name = "Malicious Ptrace Usage"
)

var R1015MaliciousPtraceUsageRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R1015ID,
	Name:        R1015Name,
	Description: "Detecting potentially malicious ptrace usage.",
	Tags:        []string{"process", "malicious"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.PtraceEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1015MaliciousPtraceUsage()
	},
}
var _ ruleengine.RuleEvaluator = (*R1015MaliciousPtraceUsage)(nil)

type R1015MaliciousPtraceUsage struct {
	BaseRule
}

func CreateRuleR1015MaliciousPtraceUsage() *R1015MaliciousPtraceUsage {
	return &R1015MaliciousPtraceUsage{}
}

func (rule *R1015MaliciousPtraceUsage) SetParameters(parameters map[string]interface{}) {

}

func (rule *R1015MaliciousPtraceUsage) Name() string {
	return R1015Name
}

func (rule *R1015MaliciousPtraceUsage) ID() string {
	return R1015ID
}

func (rule *R1015MaliciousPtraceUsage) DeleteRule() {
}

func (rule *R1015MaliciousPtraceUsage) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, _ objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.PtraceEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	_, ok := event.(*tracerptracetype.Event)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	return ruleengine.DetectionResult{IsFailure: true, Payload: nil}
}

// Won't be used, because the rule is not profile dependent
func (rule *R1015MaliciousPtraceUsage) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	return detectionResult, nil
}

func (rule *R1015MaliciousPtraceUsage) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	ptraceEvent, _ := event.(*tracerptracetype.Event)

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s", ptraceEvent.ExePath, ptraceEvent.Comm)),
			AlertName:   rule.Name(),
			InfectedPID: ptraceEvent.Pid,
			Severity:    R1015MaliciousPtraceUsageRuleDescriptor.Priority,
			Identifiers: &common.Identifiers{
				Process: &common.ProcessEntity{
					Name: ptraceEvent.Comm,
				},
				File: &common.FileEntity{
					Name:      filepath.Base(ptraceEvent.ExePath),
					Directory: filepath.Dir(ptraceEvent.ExePath),
				},
			},
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: ptraceEvent.Comm,
				PPID: ptraceEvent.PPid,
				PID:  ptraceEvent.Pid,
				Uid:  &ptraceEvent.Uid,
				Gid:  &ptraceEvent.Gid,
				Path: ptraceEvent.ExePath,
			},
			ContainerID: ptraceEvent.Runtime.ContainerID,
		},
		TriggerEvent: ptraceEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Malicious ptrace usage detected from: %s on PID: %d", ptraceEvent.Comm, ptraceEvent.Pid),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   ptraceEvent.GetPod(),
			PodLabels: ptraceEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}
}

func (rule *R1015MaliciousPtraceUsage) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1015MaliciousPtraceUsageRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.NotRequired,
		},
	}
}
