package ruleengine

import (
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"

	ruleenginetypes "github.com/kubescape/node-agent/pkg/ruleengine/types"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestR0003UnexpectedSystemCall(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0003UnexpectedSystemCall()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
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

	// Test with nil application profile
	ruleResult := ProcessRuleEvaluationTest(r, utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since no syscall event")
	}

	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{
					{
						Name: "test",
						Syscalls: []string{
							"test",
						},
					},
				},
			},
		}
		objCache.SetApplicationProfile(profile)
	}
	// Test with mock application activity and syscall
	ruleResult = ProcessRuleEvaluationTest(r, utils.SyscallEventType, e, &objCache)
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since syscall is whitelisted")
	}

	objCache.SetApplicationProfile(&v1beta1.ApplicationProfile{
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name: "test",
					Syscalls: []string{
						"test1",
					},
				},
			},
		},
	})

	// Test with mock application activity and syscall
	ruleResult = ProcessRuleEvaluationTest(r, utils.SyscallEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since syscall is not whitelisted")
	}
}
