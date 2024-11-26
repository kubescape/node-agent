package ruleengine

import (
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"

	tracerrandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"
)

func TestR1007XMRCryptoMining(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1007XMRCryptoMining()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Test RandomX event
	e3 := &tracerrandomxtype.Event{
		Comm: "test",
	}

	ruleResult := r.ProcessEvent(utils.RandomXEventType, e3, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of RandomX event")
		return
	}

}
