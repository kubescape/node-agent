package ruleengine

import (
	"bytes"
	"fmt"
	"net"
	"slices"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
)

const (
	R0011ID   = "R0011"
	R0011Name = "Unexpected network traffic"
)

var R0011UnexpectedNetworkTrafficRuleDescriptor = RuleDescriptor{
	ID:          R0011ID,
	Name:        R0011Name,
	Description: "Detecting unexpected network traffic that is not whitelisted by application profile.",
	Tags:        []string{"dns", "whitelisted", "network"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.NetworkEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0011UnexpectedNetworkTraffic()
	},
}
var _ ruleengine.RuleEvaluator = (*R0011UnexpectedNetworkTraffic)(nil)

type R0011UnexpectedNetworkTraffic struct {
	BaseRule
	alertedAdresses maps.SafeMap[string, bool]
}

func CreateRuleR0011UnexpectedNetworkTraffic() *R0011UnexpectedNetworkTraffic {
	return &R0011UnexpectedNetworkTraffic{}
}

func (rule *R0011UnexpectedNetworkTraffic) Name() string {
	return R0011Name
}
func (rule *R0011UnexpectedNetworkTraffic) ID() string {
	return R0011ID
}

func (rule *R0011UnexpectedNetworkTraffic) DeleteRule() {
}

func (rule *R0011UnexpectedNetworkTraffic) handleNetworkEvent(networkEvent *tracernetworktype.Event, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	// Check if we already alerted on this address.
	if ok := rule.alertedAdresses.Has(networkEvent.DstEndpoint.Addr); ok {
		return nil
	}

	// Check if the network event is outgoing and the destination is not a private IP.
	if networkEvent.PktType == "OUTGOING" && !isPrivateIP(networkEvent.DstEndpoint.Addr) {
		nn := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood(networkEvent.Runtime.ContainerID)
		if nn == nil {
			return nil
		}

		nnContainer, err := getContainerFromNetworkNeighborhood(nn, networkEvent.GetContainer())
		if err != nil {
			return nil
		}

		domain := objCache.DnsCache().ResolveIpToDomain(networkEvent.DstEndpoint.Addr)

		// Check if the address is in the egress list and isn't in cluster.
		for _, egress := range nnContainer.Egress {
			if egress.IPAddress == networkEvent.DstEndpoint.Addr {
				return nil
			}

			// Check if we seen this dns name before and it's in-cluster address and in the egress list.
			if domain != "" && (strings.HasSuffix(domain, "svc.cluster.local.") || slices.Contains(egress.DNSNames, domain)) {
				return nil
			}
		}

		// Alert on the address.
		rule.alertedAdresses.Set(networkEvent.DstEndpoint.Addr, true)
		return &GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:   rule.Name(),
				InfectedPID: networkEvent.Pid,
				Arguments: map[string]interface{}{
					"ip":    networkEvent.DstEndpoint.Addr,
					"port":  networkEvent.Port,
					"proto": networkEvent.Proto,
				},
				FixSuggestions: fmt.Sprintf("If this is a valid behavior, please add the IP %s to the whitelist in the application profile for the Pod %s.",
					networkEvent.DstEndpoint.Addr,
					networkEvent.GetPod(),
				),
				Severity: R0011UnexpectedNetworkTrafficRuleDescriptor.Priority,
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
				RuleDescription: fmt.Sprintf("Unexpected network communication to: %s:%d using %s from: %s", networkEvent.DstEndpoint.Addr, networkEvent.Port, networkEvent.Proto, networkEvent.GetContainer()),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName:   networkEvent.GetPod(),
				PodLabels: networkEvent.K8s.PodLabels,
			},
			RuleID: rule.ID(),
		}
	}

	return nil
}

func (rule *R0011UnexpectedNetworkTraffic) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.NetworkEventType {
		return nil
	}

	networkEvent, ok := event.(*tracernetworktype.Event)
	if !ok {
		return nil
	}
	return rule.handleNetworkEvent(networkEvent, objCache)

}

func (rule *R0011UnexpectedNetworkTraffic) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0011UnexpectedNetworkTrafficRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}

func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check if IP is in private IP ranges
	privateIPRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
	}

	for _, r := range privateIPRanges {
		if bytes.Compare(parsedIP, r.start) >= 0 && bytes.Compare(parsedIP, r.end) <= 0 {
			return true
		}
	}

	return false
}
