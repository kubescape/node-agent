package ruleengine

import (
	"node-agent/pkg/utils"
	"testing"

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestR0005UnexpectedDomainRequest(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0005UnexpectedDomainRequest()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create a domain request event
	e := &tracerdnstype.Event{
		DNSName: "test.com",
	}

	// Test with nil appProfileAccess
	ruleResult := r.ProcessEvent(utils.DnsEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to not be nil since no appProfile")
	}

	// Test with whitelisted domain
	objCache := RuleObjectCacheMock{}
	objCache.SetNetworkNeighbors(&v1beta1.NetworkNeighbors{
		Spec: v1beta1.NetworkNeighborsSpec{
			Egress: []v1beta1.NetworkNeighbor{
				{
					DNS: "test.com",
				},
			},
		},
	})
	ruleResult = r.ProcessEvent(utils.DnsEventType, e, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since domain is whitelisted")
	}

}
