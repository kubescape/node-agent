package ruleengine

import (
	"bytes"
	"fmt"
	"net"
	"slices"
	"strconv"
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
	R0011Name = "Unexpected Egress Network Traffic"
)

var R0011UnexpectedEgressNetworkTrafficRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R0011ID,
	Name:        R0011Name,
	Description: "Detecting unexpected egress network traffic that is not whitelisted by application profile.",
	Tags:        []string{"dns", "whitelisted", "network"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.NetworkEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0011UnexpectedEgressNetworkTraffic()
	},
}
var _ ruleengine.RuleEvaluator = (*R0011UnexpectedEgressNetworkTraffic)(nil)

type R0011UnexpectedEgressNetworkTraffic struct {
	BaseRule
	alertedAdresses maps.SafeMap[string, bool]
}

func CreateRuleR0011UnexpectedEgressNetworkTraffic() *R0011UnexpectedEgressNetworkTraffic {
	return &R0011UnexpectedEgressNetworkTraffic{}
}

func (rule *R0011UnexpectedEgressNetworkTraffic) Name() string {
	return R0011Name
}
func (rule *R0011UnexpectedEgressNetworkTraffic) ID() string {
	return R0011ID
}

func (rule *R0011UnexpectedEgressNetworkTraffic) DeleteRule() {
}

func (rule *R0011UnexpectedEgressNetworkTraffic) handleNetworkEvent(networkEvent *tracernetworktype.Event, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	// Check if we already alerted on this endpoint.
	endpoint := fmt.Sprintf("%s:%d:%s", networkEvent.DstEndpoint.Addr, networkEvent.Port, networkEvent.Proto)
	if ok := rule.alertedAdresses.Has(endpoint); ok {
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

		if domain != "" {
			return nil
		}

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
		rule.alertedAdresses.Set(endpoint, true)
		return &GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:   rule.Name(),
				InfectedPID: networkEvent.Pid,
				Arguments: map[string]interface{}{
					"ip":    networkEvent.DstEndpoint.Addr,
					"port":  strconv.Itoa(int(networkEvent.Port)),
					"proto": networkEvent.Proto,
				},
				FixSuggestions: fmt.Sprintf("If this is a valid behavior, please add the IP %s to the whitelist in the application profile for the Pod %s.",
					networkEvent.DstEndpoint.Addr,
					networkEvent.GetPod(),
				),
				Severity: R0011UnexpectedEgressNetworkTrafficRuleDescriptor.Priority,
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
				RuleDescription: fmt.Sprintf("Unexpected egress network communication to: %s:%d using %s from: %s", networkEvent.DstEndpoint.Addr, networkEvent.Port, networkEvent.Proto, networkEvent.GetContainer()),
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

func (rule *R0011UnexpectedEgressNetworkTraffic) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.NetworkEventType {
		return nil
	}

	networkEvent, ok := event.(*tracernetworktype.Event)
	if !ok {
		return nil
	}
	return rule.handleNetworkEvent(networkEvent, objCache)

}

func (rule *R0011UnexpectedEgressNetworkTraffic) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0011UnexpectedEgressNetworkTrafficRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}

func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check if IP is localhost
	if parsedIP.IsLoopback() {
		return true
	}

	// Check if IP is in private IP ranges
	privateIPRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		// Class D (Multicast)
		{net.ParseIP("224.0.0.0"), net.ParseIP("239.255.255.255")},
		// Class E (Experimental)
		{net.ParseIP("240.0.0.0"), net.ParseIP("255.255.255.255")},
	}

	for _, r := range privateIPRanges {
		if bytes.Compare(parsedIP, r.start) >= 0 && bytes.Compare(parsedIP, r.end) <= 0 {
			return true
		}
	}

	return false
}
