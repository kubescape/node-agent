package ruleengine

import (
	"fmt"
	"slices"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
)

const (
	R1009ID   = "R1009"
	R1009Name = "Crypto Mining Related Port Communication"
)

var CommonlyUsedCryptoMinersPorts = []uint16{
	3333,  // Monero (XMR) - Stratum mining protocol (TCP).
	45700, // Monero (XMR) - Stratum mining protocol (TCP). (stratum+tcp://xmr.pool.minergate.com)
}

var R1009CryptoMiningRelatedPortRuleDescriptor = RuleDescriptor{
	ID:          R1009ID,
	Name:        R1009Name,
	Description: "Detecting Crypto Miners by suspicious port usage.",
	Tags:        []string{"network", "crypto", "miners", "malicious"},
	Priority:    RulePriorityLow,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.NetworkEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1009CryptoMiningRelatedPort()
	},
}

var _ ruleengine.RuleEvaluator = (*R1009CryptoMiningRelatedPort)(nil)

type R1009CryptoMiningRelatedPort struct {
	BaseRule
}

func CreateRuleR1009CryptoMiningRelatedPort() *R1009CryptoMiningRelatedPort {
	return &R1009CryptoMiningRelatedPort{}
}

func (rule *R1009CryptoMiningRelatedPort) Name() string {
	return R1009Name
}

func (rule *R1009CryptoMiningRelatedPort) ID() string {
	return R1009ID
}

func (rule *R1009CryptoMiningRelatedPort) DeleteRule() {
}

func (rule *R1009CryptoMiningRelatedPort) ProcessEvent(eventType utils.EventType, event interface{}, _ objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.NetworkEventType {
		return nil
	}

	if networkEvent, ok := event.(*tracernetworktype.Event); ok {
		if networkEvent.Proto == "TCP" && networkEvent.PktType == "OUTGOING" && slices.Contains(CommonlyUsedCryptoMinersPorts, networkEvent.Port) {
			ruleFailure := GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					AlertName:      rule.Name(),
					InfectedPID:    networkEvent.Pid,
					FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
					Severity:       R1009CryptoMiningRelatedPortRuleDescriptor.Priority,
				},
				RuntimeProcessDetails: apitypes.ProcessTree{
					ProcessTree: apitypes.Process{
						Comm: networkEvent.Comm,
						Gid:  &networkEvent.Gid,
						PID:  networkEvent.Pid,
						Uid:  &networkEvent.Uid,
					},
					ContainerID: networkEvent.Runtime.ContainerID,
				},
				TriggerEvent: networkEvent.Event,
				RuleAlert: apitypes.RuleAlert{
					RuleDescription: fmt.Sprintf("Communication on a commonly used crypto mining port: %d in: %s", networkEvent.Port, networkEvent.GetContainer()),
				},
				RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
					PodName: networkEvent.GetPod(),
				},
				RuleID: rule.ID(),
			}

			return &ruleFailure
		}
	}

	return nil
}

func (rule *R1009CryptoMiningRelatedPort) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1009CryptoMiningRelatedPortRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
