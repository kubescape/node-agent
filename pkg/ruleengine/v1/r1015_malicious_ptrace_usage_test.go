package ruleengine

import (
	"testing"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/v1/ruleprocess"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	tracerptracetype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer/types"
)

const (
	// Define the ptrace constants
	PTRACE_SETREGS  = 13
	PTRACE_POKETEXT = 4
	PTRACE_POKEDATA = 5
)

func TestR1015MaliciousPtraceUsage(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1015MaliciousPtraceUsage() // Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{
					{
						Name: "test",
						Opens: []v1beta1.OpenCalls{
							{
								Path:  "/test",
								Flags: []string{"O_RDONLY"},
							},
						},
						Execs: []v1beta1.ExecCalls{
							{
								Path: "/usr/sbin/groupadd",
								Args: []string{"test"},
							},
						},
					},
				},
			},
		}
		objCache.SetApplicationProfile(profile)
	}

	// Create a ptrace event for a disallowed request (malicious request)
	e := &tracerptracetype.Event{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm:    "malicious_process",
		Pid:     1234,
		PPid:    5678,
		Uid:     1000,
		Gid:     1000,
		ExePath: "/path/to/malicious_process",
		Request: PTRACE_SETREGS, // Malicious ptrace request
	}

	ruleResult := ruleprocess.ProcessRule(r, utils.PtraceEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to be Failure because of malicious ptrace request: %d", e.Request)
		return
	}

	// Check that the ruleResult contains the expected details
	genericRuleFailure, ok := ruleResult.(*GenericRuleFailure)
	if !ok {
		t.Errorf("Expected ruleResult to be of type GenericRuleFailure")
		return
	}

	if genericRuleFailure.BaseRuntimeAlert.AlertName != r.Name() {
		t.Errorf("Expected AlertName to be %s, got %s", r.Name(), genericRuleFailure.BaseRuntimeAlert.AlertName)
	}
	if genericRuleFailure.BaseRuntimeAlert.InfectedPID != e.Pid {
		t.Errorf("Expected InfectedPID to be %d, got %d", e.Pid, genericRuleFailure.BaseRuntimeAlert.InfectedPID)
	}

	// Test with a disallowed request but recognized process
	e.Comm = "processA"         // Allowed process
	e.Request = PTRACE_POKETEXT // Malicious ptrace request
	ruleResult = ruleprocess.ProcessRule(r, utils.PtraceEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to be Failure because of malicious ptrace request: %d, even though process is allowed", e.Request)
		return
	}

	// Test with an unrecognized process and malicious request
	e.Comm = "unknown_process"
	e.Request = PTRACE_POKEDATA // Malicious ptrace request
	ruleResult = ruleprocess.ProcessRule(r, utils.PtraceEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to be Failure because of unknown process with malicious ptrace request: %d", e.Request)
	}
}
