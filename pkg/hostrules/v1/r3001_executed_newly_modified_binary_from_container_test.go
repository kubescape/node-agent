package hostrules

import (
	"os"
	"testing"
	"time"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type RuleObjectCacheMock struct{}

func createTempFile(t *testing.T, timeOffset time.Duration) string {
	tmpfile, err := os.CreateTemp("", "test-binary-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpfile.Write([]byte("test binary")); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	if timeOffset != 0 {
		modTime := time.Now().Add(timeOffset)
		err = os.Chtimes(tmpfile.Name(), modTime, modTime)
		if err != nil {
			t.Fatalf("Failed to set file times: %v", err)
		}
	}

	return tmpfile.Name()
}

func TestR3001UnexpectedProcessLaunched(t *testing.T) {
	// Create a new rule
	r := CreateRuleR3001UnexpectedProcessLaunched()
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create test files
	newFile := createTempFile(t, 0)               // Just created
	oldFile := createTempFile(t, -10*time.Minute) // Created 10 minutes ago

	// Cleanup
	defer os.Remove(newFile)
	defer os.Remove(oldFile)

	// Test cases
	tests := []struct {
		name          string
		event         *events.ExecEvent
		eventType     utils.EventType
		expectFailure bool
	}{
		{
			name: "Newly modified binary execution",
			event: &events.ExecEvent{
				Event: tracerexectype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "test-container",
									PodName:       "test-pod",
									Namespace:     "test-namespace",
								},
							},
						},
					},
					Comm:    "test-process",
					Args:    []string{newFile, "--flag1", "--flag2"},
					Retval:  0,
					Uid:     1000,
					Gid:     1000,
					Pid:     1234,
					Ppid:    5678,
					ExePath: newFile,
				},
			},
			eventType:     utils.ExecveEventType,
			expectFailure: true,
		},
		{
			name: "Old binary execution",
			event: &events.ExecEvent{
				Event: tracerexectype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "test-container",
								},
							},
						},
					},
					Comm:    "test-process",
					Args:    []string{oldFile, "--test"},
					Retval:  0,
					Pid:     1234,
					ExePath: oldFile,
				},
			},
			eventType:     utils.ExecveEventType,
			expectFailure: false,
		},
		{
			name: "Wrong event type",
			event: &events.ExecEvent{
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
					Comm: "test",
					Args: []string{"test"},
				},
			},
			eventType:     utils.PtraceEventType,
			expectFailure: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Process the event
			ruleResult := r.ProcessEvent(tc.eventType, tc.event, nil)

			// Verify results
			if tc.expectFailure {
				if ruleResult == nil {
					t.Errorf("Expected rule failure but got nil")
					return
				}

				failure, ok := ruleResult.(*ruleenginev1.GenericRuleFailure)
				if !ok {
					t.Errorf("Expected GenericRuleFailure type")
					return
				}

				// Verify failure details
				if failure.BaseRuntimeAlert.AlertName != R3001Name {
					t.Errorf("Expected alert name %s, got %s", R3001Name, failure.BaseRuntimeAlert.AlertName)
				}

			} else if ruleResult != nil {
				t.Errorf("Expected no failure but got: %v", ruleResult)
			}
		})
	}
}
