package ruleengine

import (
	"testing"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR1000ExecFromMaliciousSource(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1000ExecFromMaliciousSource()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}
	// Create an exec event
	e := &events.ExecEvent{
		Event: tracerexectype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					K8s: eventtypes.K8sMetadata{
						BasicK8sMetadata: eventtypes.BasicK8sMetadata{
							ContainerName: "test",
						},
					},
				},
			},
			Comm: "/test",
			Args: []string{},
		},
	}

	ruleResult := r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since test is not a malicious exec")
	}

	e.Comm = "/proc/self/fd/3"

	ruleResult = r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is malicious")
	}

	e.Cwd = "/"

	e.Comm = "/run.sh"

	ruleResult = r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since exec is not malicious")
	}

	e.Comm = "./run.sh"

	ruleResult = r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since exec is not malicious")
	}

	e.Comm = "/dev/shm/run.sh"

	ruleResult = r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is malicious")
	}

	e.Comm = "./dev/shm/run.sh"

	ruleResult = r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is malicious")
	}

	e.Cwd = "/dev/shm"
	e.Comm = "./run.sh"

	ruleResult = r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is malicious")
	}

	e.Comm = "./run.sh -al"

	ruleResult = r.ProcessEvent(utils.ExecveEventType, e, &RuleObjectCacheMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is malicious")
	}
}
