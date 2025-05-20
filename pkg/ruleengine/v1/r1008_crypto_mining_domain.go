package ruleengine

import (
	"fmt"
	"slices"

	"github.com/goradd/maps"
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

var commonlyUsedCryptoMinersDomains = []string{
	"2cryptocalc.com.",
	"2miners.com.",
	"antpool.com.",
	"asia1.ethpool.org.",
	"bohemianpool.com.",
	"botbox.dev.",
	"btm.antpool.com.",
	"c3pool.com.",
	"c4pool.org.",
	"ca.minexmr.com.",
	"cn.stratum.slushpool.com.",
	"dash.antpool.com.",
	"data.miningpoolstats.stream.",
	"de.minexmr.com.",
	"eth-ar.dwarfpool.com.",
	"eth-asia.dwarfpool.com.",
	"eth-asia1.nanopool.org.",
	"eth-au.dwarfpool.com.",
	"eth-au1.nanopool.org.",
	"eth-br.dwarfpool.com.",
	"eth-cn.dwarfpool.com.",
	"eth-cn2.dwarfpool.com.",
	"eth-eu.dwarfpool.com.",
	"eth-eu1.nanopool.org.",
	"eth-eu2.nanopool.org.",
	"eth-hk.dwarfpool.com.",
	"eth-jp1.nanopool.org.",
	"eth-ru.dwarfpool.com.",
	"eth-ru2.dwarfpool.com.",
	"eth-sg.dwarfpool.com.",
	"eth-us-east1.nanopool.org.",
	"eth-us-west1.nanopool.org.",
	"eth-us.dwarfpool.com.",
	"eth-us2.dwarfpool.com.",
	"eth.antpool.com.",
	"eu.stratum.slushpool.com.",
	"eu1.ethermine.org.",
	"eu1.ethpool.org.",
	"fastpool.xyz.",
	"fr.minexmr.com.",
	"kriptokyng.com.",
	"mine.moneropool.com.",
	"mine.xmrpool.net.",
	"miningmadness.com.",
	"monero.cedric-crispin.com.",
	"monero.crypto-pool.fr.",
	"monero.fairhash.org.",
	"monero.hashvault.pro.",
	"monero.herominers.com.",
	"monerod.org.",
	"monerohash.com.",
	"moneroocean.stream.",
	"monerop.com.",
	"multi-pools.com.",
	"p2pool.io.",
	"pool.kryptex.com.",
	"pool.minexmr.com.",
	"pool.monero.hashvault.pro.",
	"pool.rplant.xyz.",
	"pool.supportxmr.com.",
	"pool.xmr.pt.",
	"prohashing.com.",
	"rx.unmineable.com.",
	"sg.minexmr.com.",
	"sg.stratum.slushpool.com.",
	"skypool.org.",
	"solo-xmr.2miners.com.",
	"ss.antpool.com.",
	"stratum-btm.antpool.com.",
	"stratum-dash.antpool.com.",
	"stratum-eth.antpool.com.",
	"stratum-ltc.antpool.com.",
	"stratum-xmc.antpool.com.",
	"stratum-zec.antpool.com.",
	"stratum.antpool.com.",
	"supportxmr.com.",
	"trustpool.cc.",
	"us-east.stratum.slushpool.com.",
	"us1.ethermine.org.",
	"us1.ethpool.org.",
	"us2.ethermine.org.",
	"us2.ethpool.org.",
	"web.xmrpool.eu.",
	"www.domajorpool.com.",
	"www.dxpool.com.",
	"www.mining-dutch.nl.",
	"xmc.antpool.com.",
	"xmr-asia1.nanopool.org.",
	"xmr-au1.nanopool.org.",
	"xmr-eu1.nanopool.org.",
	"xmr-eu2.nanopool.org.",
	"xmr-jp1.nanopool.org.",
	"xmr-us-east1.nanopool.org.",
	"xmr-us-west1.nanopool.org.",
	"xmr.2miners.com.",
	"xmr.crypto-pool.fr.",
	"xmr.gntl.uk.",
	"xmr.nanopool.org.",
	"xmr.pool-pay.com.",
	"xmr.pool.minergate.com.",
	"xmr.solopool.org.",
	"xmr.volt-mine.com.",
	"xmr.zeropool.io.",
	"zec.antpool.com.",
	"zergpool.com.",
	"auto.c3pool.org.",
	"us.monero.herominers.com.",
}

var R1008CryptoMiningDomainCommunicationRuleDescriptor = ruleengine.RuleDescriptor{
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
	alertedDomains maps.SafeMap[string, bool]
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

func (rule *R1008CryptoMiningDomainCommunication) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{}) {
	if eventType != utils.DnsEventType {
		return false, nil
	}

	dnsEvent, ok := event.(*tracerdnstype.Event)
	if !ok {
		return false, nil
	}

	if rule.alertedDomains.Has(dnsEvent.DNSName) {
		return false, nil
	}

	if slices.Contains(commonlyUsedCryptoMinersDomains, dnsEvent.DNSName) {
		return true, dnsEvent
	}

	return false, nil
}

func (rule *R1008CryptoMiningDomainCommunication) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (bool, interface{}, error) {
	// First do basic evaluation
	ok, _ := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !ok {
		return false, nil, nil
	}

	// This rule doesn't need profile evaluation since it's based on direct detection
	return true, nil, nil
}

func (rule *R1008CryptoMiningDomainCommunication) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	dnsEvent, _ := event.(*tracerdnstype.Event)
	rule.alertedDomains.Set(dnsEvent.DNSName, true)

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s", dnsEvent.DNSName, dnsEvent.Comm)),
			AlertName:   rule.Name(),
			InfectedPID: dnsEvent.Pid,
			Severity:    R1008CryptoMiningDomainCommunicationRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm:  dnsEvent.Comm,
				Gid:   &dnsEvent.Gid,
				PID:   dnsEvent.Pid,
				Uid:   &dnsEvent.Uid,
				Pcomm: dnsEvent.Pcomm,
				Path:  dnsEvent.Exepath,
				Cwd:   dnsEvent.Cwd,
				PPID:  dnsEvent.Ppid,
			},
			ContainerID: dnsEvent.Runtime.ContainerID,
		},
		TriggerEvent: dnsEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Communication with a known crypto mining domain: %s", dnsEvent.DNSName),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   dnsEvent.GetPod(),
			PodLabels: dnsEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}
}

func (rule *R1008CryptoMiningDomainCommunication) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1008CryptoMiningDomainCommunicationRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.NotRequired,
		},
	}
}
