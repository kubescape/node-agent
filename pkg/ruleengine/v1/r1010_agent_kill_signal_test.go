package ruleengine

import (
	"node-agent/pkg/utils"
	"os"
	"testing"

	tracersignaltype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR1010AgentKillSignal(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1010AgentKillSignalRule()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}
	// Create a signal event
	e := &tracersignaltype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm:      "/test",
		TargetPid: 100,
		Signal:    "SIGKILL",
	}

	// Test with pid not being the agent
	ruleResult := r.ProcessEvent(utils.SignalEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since the pid is not the agent")
	}

	e.TargetPid = uint32(os.Getpid())
	// Test with pid being the agent
	ruleResult = r.ProcessEvent(utils.SignalEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since the pid is the agent")
	}

	// Test with signal not being SIGKILL
	e.Signal = "SIGUSR1"
	ruleResult = r.ProcessEvent(utils.SignalEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since the signal is not SIGKILL")
	}
}
