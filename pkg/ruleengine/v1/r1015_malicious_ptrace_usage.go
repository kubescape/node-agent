package ruleengine

import (
	"fmt"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	tracerptracetype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer/types"
)

const (
	R1015ID   = "R1015"
	R1015Name = "Malicious Ptrace Usage"
)

var R1015MaliciousPtraceUsageRuleDescriptor = RuleDescriptor{
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
	allowedProcesses []string
}

func CreateRuleR1015MaliciousPtraceUsage() *R1015MaliciousPtraceUsage {
	return &R1015MaliciousPtraceUsage{
		allowedProcesses: []string{"processA", "processB"}, // Example allowed processes
	}
}

func (rule *R1015MaliciousPtraceUsage) SetParameters(parameters map[string]interface{}) {
	rule.BaseRule.SetParameters(parameters)

	allowedProcessesInterface := rule.GetParameters()["allowedProcesses"]
	if allowedProcessesInterface == nil {
		return
	}

	allowedProcesses, ok := interfaceToStringSlice(allowedProcessesInterface)
	if ok {
		for _, process := range allowedProcesses {
			rule.allowedProcesses = append(rule.allowedProcesses, fmt.Sprintf("%v", process))
		}
	} else {
		logger.L().Warning("failed to convert allowedProcesses to []string", helpers.String("ruleID", rule.ID()))
	}
}

func (rule *R1015MaliciousPtraceUsage) Name() string {
	return R1015Name
}

func (rule *R1015MaliciousPtraceUsage) ID() string {
	return R1015ID
}

func (rule *R1015MaliciousPtraceUsage) DeleteRule() {
}

func (rule *R1015MaliciousPtraceUsage) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.PtraceEventType {
		return nil
	}

	ptraceEvent, ok := event.(*tracerptracetype.Event)
	if !ok {
		return nil
	}

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      rule.Name(),
			InfectedPID:    ptraceEvent.Pid,
			FixSuggestions: "Consider reviewing the application usage of ptrace.",
			Severity:       R1015MaliciousPtraceUsageRuleDescriptor.Priority,
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
	}
}
