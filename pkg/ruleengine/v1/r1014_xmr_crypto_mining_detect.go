package ruleengine

import (
	"slices"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	tracerrandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

var (
	randomx_event  bool = false
	dns_event      bool = false
	open_event     bool = false
	alertTriggered bool = false
)

const (
	R1014ID   = "R1014"
	R1014Name = "Crypto Miner detected"
)

var R1014CryptoMinerDetectedRuleDescriptor = RuleDescriptor{
	ID:          R1014ID,
	Name:        R1014Name,
	Description: "Detecting Crypto miners by domains, files and RandomX  event",
	Tags:        []string{"crypto", "miners", "malicious", "whitelisted", "network", "dns"},
	Priority:    RulePriorityCritical,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.OpenEventType,
			utils.RandomXEventType,
			utils.DnsEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1014CryptoMinerDetected()
	},
}
var _ ruleengine.RuleEvaluator = (*R1014CryptoMinerDetected)(nil)

type R1014CryptoMinerDetected struct {
	BaseRule
}

func CreateRuleR1014CryptoMinerDetected() *R1014CryptoMinerDetected {
	return &R1014CryptoMinerDetected{}
}
func (rule *R1014CryptoMinerDetected) Name() string {
	return R1014Name
}

func (rule *R1014CryptoMinerDetected) ID() string {
	return R1014ID
}

func (rule *R1014CryptoMinerDetected) DeleteRule() {
}

func (rule *R1014CryptoMinerDetected) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.OpenEventType && eventType != utils.DnsEventType && eventType != utils.RandomXEventType {
		return nil
	}

	var ApiTYpes apitypes.ProcessTree
	var TypesEvent types.Event
	var Pod string

	if openEvent, ok := event.(*traceropentype.Event); ok {

		if slices.Contains(utils.CryptoMiningFilesAccessPathsPrefix, openEvent.FullPath) {

			open_event = true
			TypesEvent.Event = openEvent.Event
			Pod = openEvent.GetPod()

			ApiTYpes = apitypes.ProcessTree{
				ProcessTree: apitypes.Process{
					Comm: openEvent.Comm,
					Gid:  &openEvent.Gid,
					PID:  openEvent.Pid,
					Uid:  &openEvent.Uid,
				},
				ContainerID: openEvent.Runtime.ContainerID,
			}
		}

	} else if randomXEvent, ok := event.(*tracerrandomxtype.Event); ok {

		randomx_event = true
		TypesEvent.Event = randomXEvent.Event
		Pod = randomXEvent.GetPod()

		ApiTYpes = apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm:       randomXEvent.Comm,
				Gid:        &randomXEvent.Gid,
				PID:        randomXEvent.Pid,
				Uid:        &randomXEvent.Uid,
				UpperLayer: &randomXEvent.UpperLayer,
				PPID:       randomXEvent.PPid,
				Hardlink:   randomXEvent.ExePath,
				Path:       randomXEvent.ExePath,
			},
			ContainerID: randomXEvent.Runtime.ContainerID,
		}

	} else if dnsEvent, ok := event.(*tracerdnstype.Event); ok {
		if slices.Contains(utils.CommonlyUsedCryptoMinersDomains, dnsEvent.DNSName) {
			dns_event = true

			TypesEvent.Event = dnsEvent.Event
			Pod = dnsEvent.GetPod()

			ApiTYpes = apitypes.ProcessTree{
				ProcessTree: apitypes.Process{
					Comm: dnsEvent.Comm,
					Gid:  &dnsEvent.Gid,
					PID:  dnsEvent.Pid,
					Uid:  &dnsEvent.Uid,
				},
				ContainerID: dnsEvent.Runtime.ContainerID,
			}
		}

	}

	if open_event && randomx_event && dns_event && !alertTriggered {
		alertTriggered = true

		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:      rule.Name(),
				InfectedPID:    ApiTYpes.ProcessTree.PID,
				FixSuggestions: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
				Severity:       R1014CryptoMinerDetectedRuleDescriptor.Priority,
			},
			RuntimeProcessDetails: ApiTYpes,
			TriggerEvent:          TypesEvent.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleDescription: "Crypto Miner Detected",
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName: Pod,
			},
			RuleID: rule.ID(),
		}

		return &ruleFailure
	}

	return nil
}

func (rule *R1014CryptoMinerDetected) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1014CryptoMinerDetectedRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
