package ruleengine

import (
	"bytes"
	"fmt"
	"net"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/rulemanager/v1/ruleprocess"
	"github.com/kubescape/node-agent/pkg/utils"
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
	startTime       time.Time
}

func CreateRuleR0011UnexpectedEgressNetworkTraffic() *R0011UnexpectedEgressNetworkTraffic {
	return &R0011UnexpectedEgressNetworkTraffic{startTime: time.Now()}
}

func (rule *R0011UnexpectedEgressNetworkTraffic) Name() string {
	return R0011Name
}
func (rule *R0011UnexpectedEgressNetworkTraffic) ID() string {
	return R0011ID
}

func (rule *R0011UnexpectedEgressNetworkTraffic) DeleteRule() {
}

func (rule *R0011UnexpectedEgressNetworkTraffic) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{}) {
	if eventType != utils.NetworkEventType {
		return false, nil
	}

	networkEvent, ok := event.(*tracernetworktype.Event)
	if !ok {
		return false, nil
	}

	// Check if the container was pre-running.
	if time.Unix(int64(networkEvent.Runtime.ContainerStartedAt), 0).Before(rule.startTime) {
		return false, nil
	}

	// Check if we already alerted on this endpoint.
	endpoint := fmt.Sprintf("%s:%d:%s", networkEvent.DstEndpoint.Addr, networkEvent.Port, networkEvent.Proto)
	if ok := rule.alertedAdresses.Has(endpoint); ok {
		return false, nil
	}

	// Check if the network event is outgoing and the destination is not a private IP.
	if networkEvent.PktType == "OUTGOING" && !isPrivateIP(networkEvent.DstEndpoint.Addr) {
		return true, networkEvent
	}

	return false, nil
}

func (rule *R0011UnexpectedEgressNetworkTraffic) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (bool, interface{}, error) {
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

	// Skip partially watched containers.
	if annotations := nn.GetAnnotations(); annotations != nil {
		if annotations["kubescape.io/completion"] == string(utils.WatchedContainerCompletionStatusPartial) {
			return false, nil, nil
		}
	}

	nnContainer, err := GetContainerFromNetworkNeighborhood(nn, networkEventTyped.GetContainer())
	if err != nil {
		return false, nil, err
	}

	domain := objCache.DnsCache().ResolveIpToDomain(networkEventTyped.DstEndpoint.Addr)
	if domain != "" {
		return false, nil, nil
	}

	// Check if the address is in the egress list and isn't in cluster.
	for _, egress := range nnContainer.Egress {
		if egress.IPAddress == networkEventTyped.DstEndpoint.Addr {
			return false, nil, nil
		}
	}

	return true, nil, nil
}

func (rule *R0011UnexpectedEgressNetworkTraffic) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	networkEvent, _ := event.(*tracernetworktype.Event)
	endpoint := fmt.Sprintf("%s:%d:%s", networkEvent.DstEndpoint.Addr, networkEvent.Port, networkEvent.Proto)
	rule.alertedAdresses.Set(endpoint, true)

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s%d", networkEvent.Comm, networkEvent.DstEndpoint.Addr, networkEvent.Port)),
			AlertName:   rule.Name(),
			InfectedPID: networkEvent.Pid,
			Arguments: map[string]interface{}{
				"ip":    networkEvent.DstEndpoint.Addr,
				"port":  networkEvent.Port,
				"proto": networkEvent.Proto,
			},
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

func (rule *R0011UnexpectedEgressNetworkTraffic) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0011UnexpectedEgressNetworkTrafficRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Required,
			ProfileType:       apitypes.NetworkProfile,
		},
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
		// APIPA (sometimes used for local dns)
		{net.ParseIP("169.254.0.0"), net.ParseIP("169.254.255.255")},
	}

	for _, r := range privateIPRanges {
		if bytes.Compare(parsedIP, r.start) >= 0 && bytes.Compare(parsedIP, r.end) <= 0 {
			return true
		}
	}

	return false
}
