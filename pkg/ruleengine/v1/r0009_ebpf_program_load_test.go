package ruleengine

import (
	"fmt"
	"node-agent/pkg/utils"
	"testing"

	ruleenginetypes "node-agent/pkg/ruleengine/types"
)

func TestR0009EbpfProgramLoad(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0009EbpfProgramLoad()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create a syscall event
	e := &ruleenginetypes.SyscallEvent{
		Comm:        "test",
		SyscallName: "test",
	}

	ruleResult := r.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since syscall is not bpf")
		return
	}

	// Create a syscall event with bpf syscall
	e.SyscallName = "bpf"

	ruleResult = r.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of bpf is used")
		return
	}
}
