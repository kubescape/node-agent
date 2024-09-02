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
	r := CreateRuleR0011UnexpectedEgressNetworkTraffic()
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
		Port: 80,
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

	// Test with non-whitelisted address with nil dns cache with different port.
	e.DstEndpoint.Addr = "5.5.5.5"
	e.Port = 443
	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since it's not whitelisted")
	}

	// Test with non-whitelisted address with nil dns cache with different port.
	e.DstEndpoint.Addr = "5.5.5.5"
	e.Port = 80
	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since it's not whitelisted and it's different port")
	}

	// Test with non-whitelisted address with nil dns cache with different port.
	e.DstEndpoint.Addr = "5.5.5.5"
	e.Port = 80
	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since we already alerted on this port")
	}

	// Test with non-whitelisted address with nil dns cache with different port.
	e.DstEndpoint.Addr = "5.5.5.5"
	e.Port = 80
	e.Proto = "UDP"
	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since it's a different protocol")
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple domain",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "Subdomain",
			input:    "sub.example.com",
			expected: "example.com",
		},
		{
			name:     "Multiple subdomains",
			input:    "a.b.c.example.com",
			expected: "example.com",
		},
		{
			name:     "Domain with trailing dot",
			input:    "example.com.",
			expected: "example.com",
		},
		{
			name:     "Subdomain with trailing dot",
			input:    "sub.example.com.",
			expected: "example.com",
		},
		{
			name:     "Single word",
			input:    "localhost",
			expected: "localhost",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Two-part domain",
			input:    "co.uk",
			expected: "co.uk",
		},
		{
			name:     "Subdomain of two-part domain",
			input:    "example.co.uk",
			expected: "co.uk",
		},
		{
			name:     "Multiple subdomains of two-part domain",
			input:    "a.b.example.co.uk",
			expected: "co.uk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractDomain(tt.input)
			if result != tt.expected {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
