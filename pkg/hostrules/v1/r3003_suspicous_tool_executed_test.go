package hostrules

import (
	"testing"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestR3003SuspiciousTool(t *testing.T) {
	// Create a new rule
	r := CreateRuleR3003SuspiciousTool()
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Test cases
	tests := []struct {
		name          string
		event         *events.ExecEvent
		eventType     utils.EventType
		expectFailure bool
		expectedTool  string
		expectedSev   int
	}{
		{
			name: "Nmap execution",
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
					Comm:    "nmap",
					Args:    []string{"/usr/bin/nmap", "-sS", "192.168.1.1"},
					Retval:  0,
					Uid:     1000,
					Gid:     1000,
					Pid:     1234,
					Ppid:    5678,
					ExePath: "/usr/bin/nmap",
				},
			},
			eventType:     utils.ExecveEventType,
			expectFailure: true,
			expectedTool:  "nmap",
			expectedSev:   1,
		},
		{
			name: "Metasploit execution",
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
					Comm:    "msfconsole",
					Args:    []string{"/usr/bin/msfconsole", "-q"},
					Retval:  0,
					Pid:     1234,
					ExePath: "/usr/bin/msfconsole",
				},
			},
			eventType:     utils.ExecveEventType,
			expectFailure: true,
			expectedTool:  "msfconsole",
			expectedSev:   3,
		},
		{
			name: "Normal binary execution",
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
					Comm:    "ls",
					Args:    []string{"/bin/ls", "-la"},
					Retval:  0,
					Pid:     1234,
					ExePath: "/bin/ls",
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
					Comm:    "nmap",
					Args:    []string{"/usr/bin/nmap"},
					ExePath: "/usr/bin/nmap",
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
				if failure.BaseRuntimeAlert.AlertName != R3003Name {
					t.Errorf("Expected alert name %s, got %s", R3003Name, failure.BaseRuntimeAlert.AlertName)
				}

				// Verify severity for known tools
				if tc.expectedSev != 0 {
					severity, ok := failure.BaseRuntimeAlert.Arguments["severity"].(int)
					if !ok {
						t.Errorf("Expected severity to be int")
						return
					}
					if severity != tc.expectedSev {
						t.Errorf("Expected severity %d, got %d", tc.expectedSev, severity)
					}
				}

			} else if ruleResult != nil {
				t.Errorf("Expected no failure but got: %v", ruleResult)
			}
		})
	}
}
