package ruleengine

import (
	"fmt"
	"slices"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/rulemanager/v1/ruleprocess"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	R1009ID   = "R1009"
	R1009Name = "Crypto Mining Related Port Communication"
)

var CommonlyUsedCryptoMinersPorts = []uint16{
	3333,  // Monero (XMR) - Stratum mining protocol (TCP).
	45700, // Monero (XMR) - Stratum mining protocol (TCP). (stratum+tcp://xmr.pool.minergate.com)
}

var R1009CryptoMiningRelatedPortRuleDescriptor = ruleengine.RuleDescriptor{
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
	alreadyNotified bool
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

func (rule *R1009CryptoMiningRelatedPort) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{}) {
	if eventType != utils.NetworkEventType {
		return false, nil
	}

	networkEvent, ok := event.(*tracernetworktype.Event)
	if !ok {
		return false, nil
	}

	if rule.alreadyNotified {
		return false, nil
	}

	if networkEvent.Proto == "TCP" && networkEvent.PktType == "OUTGOING" && slices.Contains(CommonlyUsedCryptoMinersPorts, networkEvent.Port) {
		return true, networkEvent
	}

	return false, nil
}

func (rule *R1009CryptoMiningRelatedPort) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (bool, interface{}, error) {
	// First do basic evaluation
	ok, networkEvent := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !ok {
		return false, nil, nil
	}

	networkEventTyped, _ := networkEvent.(*tracernetworktype.Event)
	nn := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood(networkEventTyped.Runtime.ContainerID)
	if nn == nil {
		return false, nil, ruleprocess.NoProfileAvailable
	}

	nnContainer, err := GetContainerFromNetworkNeighborhood(nn, networkEventTyped.GetContainer())
	if err != nil {
		return false, nil, err
	}

	// Check if the port is in the egress list
	for _, nn := range nnContainer.Egress {
		for _, port := range nn.Ports {
			if port.Port == nil {
				continue
			}
			if networkEventTyped.Port == uint16(*port.Port) {
				return false, nil, nil
			}
		}
	}

	return true, nil, nil
}

func (rule *R1009CryptoMiningRelatedPort) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	networkEvent, _ := event.(*tracernetworktype.Event)
	rule.alreadyNotified = true

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(fmt.Sprintf("%s%d", networkEvent.Comm, networkEvent.Port)),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"port":  networkEvent.Port,
				"proto": networkEvent.Proto,
				"ip":    networkEvent.DstEndpoint.Addr,
			},
			InfectedPID: networkEvent.Pid,
			Severity:    R1009CryptoMiningRelatedPortRuleDescriptor.Priority,
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
			RuleDescription: fmt.Sprintf("Communication on a commonly used crypto mining port: %d", networkEvent.Port),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   networkEvent.GetPod(),
			PodLabels: networkEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}
}

func (rule *R1009CryptoMiningRelatedPort) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1009CryptoMiningRelatedPortRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Optional,
			ProfileType:       apitypes.NetworkProfile,
		},
	}
}
