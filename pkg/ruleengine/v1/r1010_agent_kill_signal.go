package ruleengine

import (
	"fmt"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"os"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracersignaltype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	R1010ID   = "R1010"
	R1010Name = "Agent Kill Signal"
)

var R1010AgentKillSignalRuleDescriptor = RuleDescriptor{
	ID:          R1010ID,
	Name:        R1010Name,
	Description: "Detecting kill signal to agent process",
	Tags:        []string{"kill", "agent", "signal"},
	Priority:    RulePriorityCritical,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.SignalEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1010AgentKillSignalRule()
	},
}

var _ ruleengine.RuleEvaluator = (*R1010AgentKillSignalRule)(nil)

type R1010AgentKillSignalRule struct {
	BaseRule
	agentPid int
}

func CreateRuleR1010AgentKillSignalRule() *R1010AgentKillSignalRule {
	return &R1010AgentKillSignalRule{
		agentPid: os.Getpid(),
	}
}

func (rule *R1010AgentKillSignalRule) Name() string {
	return R1010Name
}

func (rule *R1010AgentKillSignalRule) ID() string {
	return R1010ID
}
func (rule *R1010AgentKillSignalRule) DeleteRule() {
}

func (rule *R1010AgentKillSignalRule) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.SignalEventType {
		return nil
	}

	signalEvent, ok := event.(*tracersignaltype.Event)
	if !ok {
		return nil
	}

	if (signalEvent.Signal == "SIGKILL" || signalEvent.Signal == "SIGTERM") && signalEvent.TargetPid == uint32(rule.agentPid) {
		logger.L().Info("Processing signal event", helpers.Interface("event", signalEvent))
		// Check if the signal is coming from Kubernetes
		if signalEvent.Runtime.ContainerID == "" {
			return nil
		}

		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:      rule.Name(),
				InfectedPID:    signalEvent.Pid,
				FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
				Severity:       R1010AgentKillSignalRuleDescriptor.Priority,
			},
			RuntimeProcessDetails: apitypes.ProcessTree{
				ProcessTree: apitypes.Process{
					Comm: signalEvent.Comm,
					Gid:  &signalEvent.Gid,
					PID:  signalEvent.Pid,
					Uid:  &signalEvent.Uid,
				},
				ContainerID: signalEvent.Runtime.ContainerID,
			},
			TriggerEvent: signalEvent.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleID:          rule.ID(),
				RuleDescription: fmt.Sprintf("%s was sent to agent from %s", signalEvent.Signal, signalEvent.GetContainer()),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName: signalEvent.GetPod(),
			},
		}

		return &ruleFailure
	}

	return nil
}

func (rule *R1010AgentKillSignalRule) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1010AgentKillSignalRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
