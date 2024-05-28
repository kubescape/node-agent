package ruleengine

import (
	"fmt"
	"node-agent/pkg/utils"
	"testing"

	tracersyscallstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
)

func TestR1002LoadKernelModule(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1002LoadKernelModule()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create a syscall event
	e := &tracersyscallstype.Event{
		Comm:    "test",
		Syscall: "test",
	}

	ruleResult := r.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since syscall is not init_module")
	}

	// Create a syscall event with init_module syscall
	e.Syscall = "init_module"

	ruleResult = r.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of init_module is not allowed")
	}

	// Create a syscall event with finit_module syscall
	r2 := CreateRuleR1002LoadKernelModule()
	e.SyscallName = "finit_module"

	ruleResult = r2.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of finit_module is not allowed")
	}
}
