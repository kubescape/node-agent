package ruleengine

import (
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"

	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestR0009EbpfProgramLoad(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0009EbpfProgramLoad()
	// Assert r is not nil
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
					},
				},
			},
		}
		objCache.SetApplicationProfile(profile)
	}

	// Create a syscall event
	e := &ruleenginetypes.SyscallEvent{
		Event: eventtypes.Event{
			CommonData: eventtypes.CommonData{
				K8s: eventtypes.K8sMetadata{
					BasicK8sMetadata: eventtypes.BasicK8sMetadata{
						ContainerName: "test",
					},
				},
			},
		},
		Comm:        "test",
		SyscallName: "test",
	}

	ruleResult := ProcessRuleEvaluationTest(r, utils.SyscallEventType, e, &objCache)
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since syscall is not bpf")
		return
	}

	// Create a syscall event with bpf syscall
	e.SyscallName = "bpf"

	ruleResult = ProcessRuleEvaluationTest(r, utils.SyscallEventType, e, &objCache)
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of bpf is used")
		return
	}
}
