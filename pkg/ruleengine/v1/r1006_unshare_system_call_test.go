package ruleengine

import (
	"fmt"
	"node-agent/pkg/utils"
	"testing"

	tracersyscallstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
)

func TestR1006UnshareSyscall(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1006UnshareSyscall()
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
		t.Errorf("Expected ruleResult to be nil since syscall is not unshare")
		return
	}

	// Create a syscall event with unshare syscall
	e.Syscall = "unshare"

	ruleResult = r.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of unshare is used")
		return
	}
}
