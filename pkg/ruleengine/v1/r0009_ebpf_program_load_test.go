package ruleengine

import (
	"fmt"
	"node-agent/pkg/utils"
	"testing"

	tracersyscallstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
)

func TestR0009EbpfProgramLoad(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0009EbpfProgramLoad()
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
		t.Errorf("Expected ruleResult to be nil since syscall is not bpf")
		return
	}

	// Create a new rule
	r2 := CreateRuleR0009EbpfProgramLoad()
	// Assert r is not nil
	if r2 == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create a syscall event with bpf syscall
	e.Syscall = "bpf"
	e.Parameters = []tracersyscallstype.SyscallParam{
		{
			Name:  "cmd",
			Value: "5", // BPF_PROG_LOAD
		},
	}

	ruleResult = r2.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of bpf is used")
		return
	}

	// Create a new rule
	r3 := CreateRuleR0009EbpfProgramLoad()
	// Assert r is not nil
	if r3 == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create a syscall event with bpf syscall but not BPF_PROG_LOAD
	e.Parameters[0].Value = "1"
	ruleResult = r3.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since syscall is bpf but not BPF_PROG_LOAD")
		return
	}
}
