package ruleengine

import (
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/rulemanager/v1/ruleprocess"
	"github.com/kubescape/node-agent/pkg/utils"

	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"
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

	ruleResult := ruleprocess.ProcessRule(r, utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since syscall is not init_module")
	}

	// Create a syscall event with init_module syscall
	e.SyscallName = "init_module"

	ruleResult = ruleprocess.ProcessRule(r, utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of init_module is not allowed")
	}

	// Create a syscall event with finit_module syscall
	r2 := CreateRuleR1002LoadKernelModule()
	e.SyscallName = "finit_module"

	ruleResult = ruleprocess.ProcessRule(r2, utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of finit_module is not allowed")
	}
}
