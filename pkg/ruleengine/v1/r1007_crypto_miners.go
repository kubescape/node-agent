package ruleengine

import (
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/ruleengine/objectcache"
	"node-agent/pkg/utils"
	"slices"

	tracerrandomxtype "node-agent/pkg/ebpf/gadgets/randomx/types"

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
)

const (
	R1007ID   = "R1007"
	R1007Name = "Crypto Miner detected"
)

var CommonlyUsedCryptoMinersPorts = []uint16{
	3333,  // Monero (XMR) - Stratum mining protocol (TCP).
	45700, // Monero (XMR) - Stratum mining protocol (TCP). (stratum+tcp://xmr.pool.minergate.com)
}

var commonlyUsedCryptoMinersDomains = []string{
	"2cryptocalc.com",
	"2miners.com",
	"antpool.com",
	"asia1.ethpool.org",
	"bohemianpool.com",
	"botbox.dev",
	"btm.antpool.com",
	"c3pool.com",
	"c4pool.org",
	"ca.minexmr.com",
	"cn.stratum.slushpool.com",
	"dash.antpool.com",
	"data.miningpoolstats.stream",
	"de.minexmr.com",
	"eth-ar.dwarfpool.com",
	"eth-asia.dwarfpool.com",
	"eth-asia1.nanopool.org",
	"eth-au.dwarfpool.com",
	"eth-au1.nanopool.org",
	"eth-br.dwarfpool.com",
	"eth-cn.dwarfpool.com",
	"eth-cn2.dwarfpool.com",
	"eth-eu.dwarfpool.com",
	"eth-eu1.nanopool.org",
	"eth-eu2.nanopool.org",
	"eth-hk.dwarfpool.com",
	"eth-jp1.nanopool.org",
	"eth-ru.dwarfpool.com",
	"eth-ru2.dwarfpool.com",
	"eth-sg.dwarfpool.com",
	"eth-us-east1.nanopool.org",
	"eth-us-west1.nanopool.org",
	"eth-us.dwarfpool.com",
	"eth-us2.dwarfpool.com",
	"eth.antpool.com",
	"eu.stratum.slushpool.com",
	"eu1.ethermine.org",
	"eu1.ethpool.org",
	"fastpool.xyz",
	"fr.minexmr.com",
	"kriptokyng.com",
	"mine.moneropool.com",
	"mine.xmrpool.net",
	"miningmadness.com",
	"monero.cedric-crispin.com",
	"monero.crypto-pool.fr",
	"monero.fairhash.org",
	"monero.hashvault.pro",
	"monero.herominers.com",
	"monerod.org",
	"monerohash.com",
	"moneroocean.stream",
	"monerop.com",
	"multi-pools.com",
	"p2pool.io",
	"pool.kryptex.com",
	"pool.minexmr.com",
	"pool.monero.hashvault.pro",
	"pool.rplant.xyz",
	"pool.supportxmr.com",
	"pool.xmr.pt",
	"prohashing.com",
	"rx.unmineable.com",
	"sg.minexmr.com",
	"sg.stratum.slushpool.com",
	"skypool.org",
	"solo-xmr.2miners.com",
	"ss.antpool.com",
	"stratum-btm.antpool.com",
	"stratum-dash.antpool.com",
	"stratum-eth.antpool.com",
	"stratum-ltc.antpool.com",
	"stratum-xmc.antpool.com",
	"stratum-zec.antpool.com",
	"stratum.antpool.com",
	"supportxmr.com",
	"trustpool.cc",
	"us-east.stratum.slushpool.com",
	"us1.ethermine.org",
	"us1.ethpool.org",
	"us2.ethermine.org",
	"us2.ethpool.org",
	"web.xmrpool.eu",
	"www.domajorpool.com",
	"www.dxpool.com",
	"www.mining-dutch.nl",
	"xmc.antpool.com",
	"xmr-asia1.nanopool.org",
	"xmr-au1.nanopool.org",
	"xmr-eu1.nanopool.org",
	"xmr-eu2.nanopool.org",
	"xmr-jp1.nanopool.org",
	"xmr-us-east1.nanopool.org",
	"xmr-us-west1.nanopool.org",
	"xmr.2miners.com",
	"xmr.crypto-pool.fr",
	"xmr.gntl.uk",
	"xmr.nanopool.org",
	"xmr.pool-pay.com",
	"xmr.pool.minergate.com",
	"xmr.solopool.org",
	"xmr.volt-mine.com",
	"xmr.zeropool.io",
	"zec.antpool.com",
	"zergpool.com",
}

var R1007CryptoMinersRuleDescriptor = RuleDescriptor{
	ID:          R1007ID,
	Name:        R1007Name,
	Description: "Detecting Crypto Miners by port, domain and randomx event.",
	Tags:        []string{"network", "crypto", "miners", "malicious", "dns"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.NetworkEventType,
			utils.DnsEventType,
			utils.RandomXEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1007CryptoMiners()
	},
}

var _ ruleengine.RuleEvaluator = (*R1007CryptoMiners)(nil)

type R1007CryptoMiners struct {
	BaseRule
}

func CreateRuleR1007CryptoMiners() *R1007CryptoMiners {
	return &R1007CryptoMiners{}
}

func (rule *R1007CryptoMiners) Name() string {
	return R1007Name
}

func (rule *R1007CryptoMiners) ID() string {
	return R1007ID
}

func (rule *R1007CryptoMiners) DeleteRule() {
}

func (rule *R1007CryptoMiners) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.NetworkEventType && eventType != utils.DnsEventType && eventType != utils.RandomXEventType {
		return nil
	}

	if randomXEvent, ok := event.(*tracerrandomxtype.Event); ok {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			ContainerId:      randomXEvent.Runtime.ContainerID,
			Err:              "Possible Crypto Miner detected",
			FailureEvent:     utils.RandomxToGeneralEvent(randomXEvent),
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			RulePriority:     R1007CryptoMinersRuleDescriptor.Priority,
		}
	} else if networkEvent, ok := event.(*tracernetworktype.Event); ok {
		if networkEvent.Proto == "TCP" && networkEvent.PktType == "OUTGOING" && slices.Contains(CommonlyUsedCryptoMinersPorts, networkEvent.Port) {
			return &GenericRuleFailure{
				RuleName:         rule.Name(),
				RuleID:           rule.ID(),
				ContainerId:      networkEvent.Runtime.ContainerID,
				Err:              "Possible Crypto Miner port detected",
				FailureEvent:     utils.NetworkToGeneralEvent(networkEvent),
				FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
				RulePriority:     R1007CryptoMinersRuleDescriptor.Priority,
			}
		}
	} else if dnsEvent, ok := event.(*tracerdnstype.Event); ok {
		if slices.Contains(commonlyUsedCryptoMinersDomains, dnsEvent.DNSName) {
			return &GenericRuleFailure{
				RuleName:         rule.Name(),
				RuleID:           rule.ID(),
				ContainerId:      dnsEvent.Runtime.ContainerID,
				Err:              "Possible Crypto Miner domain detected",
				FailureEvent:     utils.DnsToGeneralEvent(dnsEvent),
				FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
				RulePriority:     R1007CryptoMinersRuleDescriptor.Priority,
			}
		}
	}

	return nil
}

func (rule *R1007CryptoMiners) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1007CryptoMinersRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
