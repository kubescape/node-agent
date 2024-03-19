package ruleengine

import (
	"node-agent/pkg/utils"
	"testing"

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/kubescape/kapprofiler/pkg/collector"
	"github.com/kubescape/kapprofiler/pkg/tracing"
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
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   0,
		},
		DnsName: "test.com",
		Addresses: []string{
			"test",
		},
	}

	// Test with nil appProfileAccess
	ruleResult := r.ProcessEvent(utils.DnsEventType, e, nil, nil)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since no appProfile")
	}

	// Test with empty appProfileAccess
	ruleResult = r.ProcessEvent(utils.DnsEventType, e, &MockAppProfileAccess{}, nil)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since domain is not whitelisted")
	}

	// Test with whitelisted domain
	ruleResult = r.ProcessEvent(utils.DnsEventType, e, &MockAppProfileAccess{
		Dns: []collector.DnsCalls{
			{
				DnsName: "test.com",
			},
		},
	}, nil)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since domain is whitelisted")
	}

}
