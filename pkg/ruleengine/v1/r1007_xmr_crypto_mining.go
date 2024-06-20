package ruleengine

import (
	"fmt"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	tracerrandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R1007ID   = "R1007"
	R1007Name = "XMR Crypto Mining Detection"
)

var R1007XMRCryptoMiningRuleDescriptor = RuleDescriptor{
	ID:          R1007ID,
	Name:        R1007Name,
	Description: "Detecting XMR Crypto Miners by randomx algorithm usage.",
	Tags:        []string{"crypto", "miners", "malicious"},
	Priority:    RulePriorityCritical,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.RandomXEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1007XMRCryptoMining()
	},
}

var _ ruleengine.RuleEvaluator = (*R1007XMRCryptoMining)(nil)

type R1007XMRCryptoMining struct {
	BaseRule
}

func CreateRuleR1007XMRCryptoMining() *R1007XMRCryptoMining {
	return &R1007XMRCryptoMining{}
}

func (rule *R1007XMRCryptoMining) Name() string {
	return R1007Name
}

func (rule *R1007XMRCryptoMining) ID() string {
	return R1007ID
}

func (rule *R1007XMRCryptoMining) DeleteRule() {
}

func (rule *R1007XMRCryptoMining) ProcessEvent(eventType utils.EventType, event interface{}, _ objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.RandomXEventType {
		return nil
	}

	if randomXEvent, ok := event.(*tracerrandomxtype.Event); ok {
		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:      rule.Name(),
				InfectedPID:    randomXEvent.Pid,
				FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
				Severity:       R1007XMRCryptoMiningRuleDescriptor.Priority,
			},
			RuntimeProcessDetails: apitypes.ProcessTree{
				ProcessTree: apitypes.Process{
					Comm:       randomXEvent.Comm,
					Gid:        &randomXEvent.Gid,
					PID:        randomXEvent.Pid,
					Uid:        &randomXEvent.Uid,
					UpperLayer: &randomXEvent.UpperLayer,
					PPID:       randomXEvent.PPid,
				},
				ContainerID: randomXEvent.Runtime.ContainerID,
			},
			TriggerEvent: randomXEvent.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleDescription: fmt.Sprintf("XMR Crypto Miner process: (%s) executed in: %s", randomXEvent.Comm, randomXEvent.GetContainer()),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName: randomXEvent.GetPod(),
			},
			RuleID: rule.ID(),
		}

		return &ruleFailure
	}

	return nil
}

func (rule *R1007XMRCryptoMining) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1007XMRCryptoMiningRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
