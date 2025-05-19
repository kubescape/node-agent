package ruleengine

import (
	"testing"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	traceriouringtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func TestR1030UnexpectedIouringOperation(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1030UnexpectedIouringOperation()
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Setup mock object cache
	objCache := RuleObjectCacheMock{}
	profile := objCache.ApplicationProfileCache().GetApplicationProfile("test")
	if profile == nil {
		profile = &v1beta1.ApplicationProfile{
			Spec: v1beta1.ApplicationProfileSpec{
				Containers: []v1beta1.ApplicationProfileContainer{
					{
						Name: "test",
						PolicyByRuleId: map[string]v1beta1.RulePolicy{
							R1030ID: {
								AllowedProcesses: []string{"/usr/bin/allowed-process"},
							},
						},
					},
				},
			},
		}
		objCache.SetApplicationProfile(profile)
	}

	// Test cases
	testCases := []struct {
		name          string
		event         *traceriouringtype.Event
		expectedAlert bool
	}{
		{
			name: "Valid io_uring operation with known opcode",
			event: &traceriouringtype.Event{
				Event: eventtypes.Event{
					CommonData: eventtypes.CommonData{
						K8s: eventtypes.K8sMetadata{
							BasicK8sMetadata: eventtypes.BasicK8sMetadata{
								ContainerName: "test",
							},
						},
					},
				},
				Identifier: "test-process",
				Opcode:     1, // IORING_OP_NOP
				Flags:      0x0,
				UserData:   123,
				Comm:       "test-process",
			},
			expectedAlert: true,
		},
		{
			name: "Whitelisted process",
			event: &traceriouringtype.Event{
				Event: eventtypes.Event{
					CommonData: eventtypes.CommonData{
						K8s: eventtypes.K8sMetadata{
							BasicK8sMetadata: eventtypes.BasicK8sMetadata{
								ContainerName: "test",
							},
						},
					},
				},
				Identifier: "/usr/bin/allowed-process",
				Opcode:     1,
				Flags:      0x0,
				UserData:   123,
				Comm:       "/usr/bin/allowed-process",
			},
			expectedAlert: false,
		},
		{
			name: "Unknown opcode",
			event: &traceriouringtype.Event{
				Event: eventtypes.Event{
					CommonData: eventtypes.CommonData{
						K8s: eventtypes.K8sMetadata{
							BasicK8sMetadata: eventtypes.BasicK8sMetadata{
								ContainerName: "test",
							},
						},
					},
				},
				Identifier: "test-process",
				Opcode:     999, // Invalid opcode
				Flags:      0x0,
				UserData:   123,
				Comm:       "test-process",
			},
			expectedAlert: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ruleResult := ProcessRuleEvaluationTest(r, utils.IoUringEventType, tc.event, &objCache)

			if tc.expectedAlert && ruleResult == nil {
				t.Errorf("Expected alert for io_uring operation but got nil")
			}
			if !tc.expectedAlert && ruleResult != nil {
				t.Errorf("Expected no alert for io_uring operation but got: %v", ruleResult)
			}
		})
	}

	// Test wrong event type
	wrongEvent := &traceriouringtype.Event{}
	ruleResult := ProcessRuleEvaluationTest(r, utils.HardlinkEventType, wrongEvent, &objCache)
	if ruleResult != nil {
		t.Errorf("Expected no alert for wrong event type but got: %v", ruleResult)
	}

	// Test evaluation with invalid event type
	if ok, _ := r.EvaluateRule(utils.HardlinkEventType, wrongEvent, objCache.K8sObjectCache()); ok {
		t.Error("Expected EvaluateRule to return false for wrong event type")
	}

	// Test requirements
	reqs := r.Requirements()
	if len(reqs.RequiredEventTypes()) != 1 || reqs.RequiredEventTypes()[0] != utils.IoUringEventType {
		t.Error("Expected Requirements to return IoUringEventType")
	}
}
