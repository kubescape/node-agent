package ruleengine

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
)

func TestR1009CryptoMiningRelatedPort(t *testing.T) {
	rule := &R1009CryptoMiningRelatedPort{}

	// Test when eventType is not NetworkEventType
	eventType := utils.RandomXEventType
	event := &tracernetworktype.Event{}
	result := rule.ProcessEvent(eventType, event, &RuleObjectCacheMock{})
	if result != nil {
		t.Errorf("Expected nil, got %v", result)
	}

	// Test when event is not of type *tracernetworktype.Event
	eventType = utils.NetworkEventType
	event2 := &tracerexectype.Event{}
	result = rule.ProcessEvent(eventType, event2, &RuleObjectCacheMock{})
	if result != nil {
		t.Errorf("Expected nil, got %v", result)
	}

	// Test when event meets all conditions to return a ruleFailure
	eventType = utils.NetworkEventType
	event = &tracernetworktype.Event{
		Proto:   "TCP",
		PktType: "OUTGOING",
		Port:    CommonlyUsedCryptoMinersPorts[0],
		Comm:    "testComm",
		Gid:     1,
		Pid:     1,
		Uid:     1,
	}
	result = rule.ProcessEvent(eventType, event, &RuleObjectCacheMock{})
	if result == nil {
		t.Errorf("Expected ruleFailure, got nil")
	}
}
