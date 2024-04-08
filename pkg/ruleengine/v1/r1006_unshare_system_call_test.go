package ruleengine

import (
	"fmt"
	"github.com/kubescape/node-agent/pkg/utils"
	"testing"

	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"
)

func TestR1006UnshareSyscall(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1006UnshareSyscall()
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
		t.Errorf("Expected ruleResult to be nil since syscall is not unshare")
		return
	}

	// Create a syscall event with unshare syscall
	e.SyscallName = "unshare"

	ruleResult = r.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of unshare is used")
		return
	}
}
