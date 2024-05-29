package ruleengine

import (
	"fmt"
	"node-agent/pkg/utils"
	"testing"

	tracersyscallstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
)

func TestR1010UnshareSyscall(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1010SymlinkCreatedOverSensitiveFile() // Assert r is not nil
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
		t.Errorf("Expected ruleResult to be nil since syscall is not symlink")
		return
	}

	// Create a syscall event with symlink syscall
	e.Syscall = "symlink"
	e.Parameters = []tracersyscallstype.SyscallParam{
		{
			Name:  "target",
			Value: "/etc/shadow",
		},
		{
			Name:  "linkpath",
			Value: "/test/link",
		},
	}

	ruleResult = r.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of symlink is used over sensitive file")
		return
	}

	e.Parameters[0].Value = "/etc/abc"
	ruleResult = r.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since symlink is not used over sensitive file")
		return
	}
}
