package ruleengine

import (
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

func TestR1008CryptoMiningDomainCommunication(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1008CryptoMiningDomainCommunication()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create dns event
	e2 := &tracerdnstype.Event{
		DNSName: "xmr.gntl.uk.",
	}

	ruleResult := ProcessRuleEvaluationTest(r, utils.DnsEventType, e2, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of dns name is in the commonly used crypto miners domains")
		return
	}

	e2.DNSName = "amit.com"

	ruleResult = ProcessRuleEvaluationTest(r, utils.DnsEventType, e2, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since dns name is not in the commonly used crypto miners domains")
		return
	}
}
