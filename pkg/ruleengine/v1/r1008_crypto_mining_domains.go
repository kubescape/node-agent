package ruleengine

import (
	"fmt"
	"slices"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

const (
	R1008ID   = "R1008"
	R1008Name = "Crypto Mining Domain Communication"
)

var R1008CryptoMiningDomainCommunicationRuleDescriptor = RuleDescriptor{
	ID:          R1008ID,
	Name:        R1008Name,
	Description: "Detecting Crypto miners communication by domain",
	Tags:        []string{"network", "crypto", "miners", "malicious", "dns"},
	Priority:    RulePriorityCritical,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.DnsEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1008CryptoMiningDomainCommunication()
	},
}

var _ ruleengine.RuleEvaluator = (*R1008CryptoMiningDomainCommunication)(nil)

type R1008CryptoMiningDomainCommunication struct {
	BaseRule
}

func CreateRuleR1008CryptoMiningDomainCommunication() *R1008CryptoMiningDomainCommunication {
	return &R1008CryptoMiningDomainCommunication{}
}

func (rule *R1008CryptoMiningDomainCommunication) Name() string {
	return R1008Name
}

func (rule *R1008CryptoMiningDomainCommunication) ID() string {
	return R1008ID
}

func (rule *R1008CryptoMiningDomainCommunication) DeleteRule() {
}

func (rule *R1008CryptoMiningDomainCommunication) ProcessEvent(eventType utils.EventType, event interface{}, _ objectcache.ObjectCache) ruleengine.RuleFailure {

	if eventType != utils.DnsEventType {
		return nil
	}

	if dnsEvent, ok := event.(*tracerdnstype.Event); ok {

		if slices.Contains(utils.CommonlyUsedCryptoMinersDomains, dnsEvent.DNSName) {
			ruleFailure := GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
					AlertName:      rule.Name(),
					InfectedPID:    dnsEvent.Pid,
					FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
					Severity:       R1008CryptoMiningDomainCommunicationRuleDescriptor.Priority,
				},
				RuntimeProcessDetails: apitypes.ProcessTree{
					ProcessTree: apitypes.Process{
						Comm: dnsEvent.Comm,
						Gid:  &dnsEvent.Gid,
						PID:  dnsEvent.Pid,
						Uid:  &dnsEvent.Uid,
					},
					ContainerID: dnsEvent.Runtime.ContainerID,
				},
				TriggerEvent: dnsEvent.Event,
				RuleAlert: apitypes.RuleAlert{
					RuleDescription: fmt.Sprintf("Communication with a known crypto mining domain: %s in: %s", dnsEvent.DNSName, dnsEvent.GetContainer()),
				},
				RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
					PodName: dnsEvent.GetPod(),
				},
				RuleID: rule.ID(),
			}

			return &ruleFailure
		}
	}

	return nil
}

func (rule *R1008CryptoMiningDomainCommunication) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1008CryptoMiningDomainCommunicationRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
