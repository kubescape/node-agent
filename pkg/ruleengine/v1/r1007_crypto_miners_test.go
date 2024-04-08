package ruleengine

import (
	"fmt"
	"github.com/kubescape/node-agent/pkg/utils"
	"testing"

	tracerrandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"

	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR1007CryptoMiners(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1007CryptoMiners()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create network event
	e := &tracernetworktype.Event{
		PktType: "OUTGOING",
		Proto:   "TCP",
		Port:    2222,
		DstEndpoint: types.L3Endpoint{
			Addr: "1.1.1.1",
		},
	}

	ruleResult := r.ProcessEvent(utils.NetworkEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since dst port is not in the commonly used crypto miners ports")
		return
	}

	// Create network event with dst port 3333
	e.Port = 3333

	ruleResult = r.ProcessEvent(utils.NetworkEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of dst port is in the commonly used crypto miners ports")
		return
	}

	// Create dns event
	e2 := &tracerdnstype.Event{
		DNSName: "xmr.gntl.uk",
	}

	ruleResult = r.ProcessEvent(utils.DnsEventType, e2, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of dns name is in the commonly used crypto miners domains")
		return
	}

	// Test RandomX event
	e3 := &tracerrandomxtype.Event{
		Comm: "test",
	}

	ruleResult = r.ProcessEvent(utils.RandomXEventType, e3, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of RandomX event")
		return
	}

}
