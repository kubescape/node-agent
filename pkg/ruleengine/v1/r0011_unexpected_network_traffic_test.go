package ruleengine

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"

	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestR0011UnexpectedNetworkTraffic(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0011UnexpectedNetworkTraffic()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create a network request event
	e := &tracernetworktype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		PktType: "OUTGOING",
		DstEndpoint: eventtypes.L3Endpoint{
			Addr: "1.1.1.1",
		},
	}

	// Test with nil network neighborhood.
	ruleResult := r.ProcessEvent(utils.NetworkEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to not be nil since no appProfile")
	}

	// Test with whitelisted address without dns cache.
	objCache := RuleObjectCacheMock{}
	nn := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood("test")
	if nn == nil {
		nn = &v1beta1.NetworkNeighborhood{}
		nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
			Name: "test",

			Egress: []v1beta1.NetworkNeighbor{
				{
					DNS:       "test.com",
					DNSNames:  []string{"test.com"},
					IPAddress: "1.1.1.1",
				},
			},
		})

		objCache.SetNetworkNeighborhood(nn)
	}

	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since domain/adress is whitelisted")
	}

	// Test with non-whitelisted address without dns cache.
	e.DstEndpoint.Addr = "2.2.2.2"
	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since domain/adress is not whitelisted")
	}

	// Test with whitelisted address with dns cache.
	objCache.SetDnsCache(map[string]string{"2.2.2.2": "test.com"})
	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since we are able to resolve the address")
	}

	// Test with non-whitelisted address with dns cache.
	e.DstEndpoint.Addr = "3.3.3.3"
	objCache.SetDnsCache(map[string]string{"3.3.3.3": "malicious.com"})
	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since we are not able to resolve the address")
	}

	// Test with already alerted address.
	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since we already alerted on this address")
	}

	// Test with incoming packet.
	e.PktType = "INCOMING"
	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since packet is incoming")
	}

	// Test with private address.
	e.PktType = "OUTGOING"
	e.DstEndpoint.Addr = "10.0.0.1"
	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since address is private")
	}

	// Test with non-whitelisted address with dns cache empty.
	e.DstEndpoint.Addr = "4.4.4.4"
	objCache.SetDnsCache(map[string]string{})
	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since we are not able to resolve the address")
	}
}
