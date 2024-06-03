package ruleengine

import (
	"fmt"
	"node-agent/pkg/utils"
	"testing"

	tracersymlinktype "node-agent/pkg/ebpf/gadgets/symlink/types"
)

func TestR1010UnshareSyscall(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1010SymlinkCreatedOverSensitiveFile() // Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create a symlink event
	e := &tracersymlinktype.Event{
		Comm:    "test",
		OldPath: "test",
		NewPath: "test",
	}

	ruleResult := r.ProcessEvent(utils.SymlinkEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since symlink path is not sensitive")
		return
	}

	// Create a symlink event with sensitive file path
	e.OldPath = "/etc/passwd"
	e.NewPath = "/etc/abc"

	ruleResult = r.ProcessEvent(utils.SymlinkEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of symlink is used over sensitive file")
		return
	}

	e.OldPath = "/etc/abc"
	ruleResult = r.ProcessEvent(utils.SymlinkEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since symlink is not used over sensitive file")
		return
	}
}
