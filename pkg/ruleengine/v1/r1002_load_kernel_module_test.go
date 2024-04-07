package ruleengine

import (
	"fmt"
	"node-agent/pkg/utils"
	"testing"

	ruleenginetypes "node-agent/pkg/ruleengine/types"
)

func TestR1002LoadKernelModule(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1002LoadKernelModule()
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
		t.Errorf("Expected ruleResult to be nil since syscall is not init_module")
	}

	// Create a syscall event with init_module syscall
	e.SyscallName = "init_module"

	ruleResult = r.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of init_module is not allowed")
	}
}
