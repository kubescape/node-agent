package ruleengine

import (
	"node-agent/pkg/utils"
	"testing"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR1011LdPreloadHook(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1011LdPreloadHook()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}
	// // Create a exec event
	// e := &tracerexectype.Event{
	// 	Event: eventtypes.Event{
	// 		CommonData: eventtypes.CommonData{
	// 			K8s: eventtypes.K8sMetadata{
	// 				BasicK8sMetadata: eventtypes.BasicK8sMetadata{
	// 					ContainerName: "test",
	// 				},
	// 			},
	// 		},
	// 	},
	// 	Comm:       "/test",
	// 	Args:       []string{},
	// 	UpperLayer: false,
	// }

	// // Test with non existing binary
	// ruleResult := r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	// if ruleResult != nil {
	// 	t.Errorf("Expected ruleResult to be nil since exec is not in the upper layer")
	// }

	// Create open event
	e := &traceropentype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm:     "test",
		FullPath: "/etc/ld.so.preload",
		FlagsRaw: 1,
	}

	// Test with existing ld_preload file
	ruleResult := r.ProcessEvent(utils.OpenEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since ld_preload file is opened with write flag")
	}

	// Test with ld.so.preload file opened with read flag
	e.FlagsRaw = 0
	ruleResult = r.ProcessEvent(utils.OpenEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since ld_preload file is opened with read flag")
	}
}
