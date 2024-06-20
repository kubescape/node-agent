package ruleengine

import (
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"

	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
)

func TestR1012HardlinkCreatedOverSensitiveFile(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1012HardlinkCreatedOverSensitiveFile() // Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create a hardlink event
	e := &tracerhardlinktype.Event{
		Comm:    "test",
		OldPath: "test",
		NewPath: "test",
	}

	ruleResult := r.ProcessEvent(utils.HardlinkEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since hardlink path is not sensitive")
		return
	}

	// Create a hardlink event with sensitive file path
	e.OldPath = "/etc/passwd"
	e.NewPath = "/etc/abc"

	ruleResult = r.ProcessEvent(utils.HardlinkEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of hardlink is used over sensitive file")
		return
	}

	e.OldPath = "/etc/abc"
	ruleResult = r.ProcessEvent(utils.HardlinkEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since hardlink is not used over sensitive file")
		return
	}
}
