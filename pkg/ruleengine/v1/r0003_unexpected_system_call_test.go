package ruleengine

import (
	"fmt"
	"node-agent/pkg/utils"
	"testing"

	ruleenginetypes "node-agent/pkg/ruleengine/types"

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
		Comm:        "test",
		SyscallName: "test",
	}

	// Test with nil application activity
	ruleResult := r.ProcessEvent(utils.SyscallEventType, e, &RuleObjectCacheMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since no syscall event")
	}

	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test", "test")
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
	ruleResult = r.ProcessEvent(utils.SyscallEventType, e, &objCache)
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
	ruleResult = r.ProcessEvent(utils.SyscallEventType, e, &objCache)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since syscall is not whitelisted")
	}
}
