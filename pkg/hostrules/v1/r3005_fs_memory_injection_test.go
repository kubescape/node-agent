package hostrules

import (
	"testing"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestR3005MaliciousFsMemoryInjection_ProcessEvent(t *testing.T) {
	tests := []struct {
		name          string
		eventType     utils.EventType
		event         *events.OpenEvent
		expectedAlert bool
		description   string
	}{
		{
			name:      "should_alert_on_proc_mem_write",
			eventType: utils.OpenEventType,
			event: &events.OpenEvent{
				Event: traceropentype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "test-container",
									PodName:       "test-pod",
									Namespace:     "test-namespace",
								},
							},
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID: "test-container",
							},
						},
					},
					Path:     "/proc/1234/mem",
					FullPath: "/proc/../../proc/1234/mem",
					Flags:    []string{"O_WRONLY"},
				},
			},
			expectedAlert: true,
			description:   "Should alert when /proc/PID/mem is opened with write permissions",
		},
		{
			name:      "should_not_alert_on_read_only",
			eventType: utils.OpenEventType,
			event: &events.OpenEvent{
				Event: traceropentype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "test-container",
									PodName:       "test-pod",
									Namespace:     "test-namespace",
								},
							},
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID: "test-container",
							},
						},
					},
					Path:     "/proc/1234/mem",
					FullPath: "/proc/1234/mem",
					Flags:    []string{"O_RDONLY"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert when /proc/PID/mem is opened read-only",
		},
		{
			name:      "should_not_alert_on_invalid_path",
			eventType: utils.OpenEventType,
			event: &events.OpenEvent{
				Event: traceropentype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "test-container",
									PodName:       "test-pod",
									Namespace:     "test-namespace",
								},
							},
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID: "test-container",
							},
						},
					},
					Path:     "/proc/abc/mem",
					FullPath: "/proc/abc/mem",
					Flags:    []string{"O_WRONLY"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert when PID is not numeric",
		},
		{
			name:      "should_not_alert_on_different_proc_file",
			eventType: utils.OpenEventType,
			event: &events.OpenEvent{
				Event: traceropentype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "test-container",
									PodName:       "test-pod",
									Namespace:     "test-namespace",
								},
							},
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID: "test-container",
							},
						},
					},
					Path:     "/proc/1234/maps",
					FullPath: "/proc/1234/maps",
					Flags:    []string{"O_WRONLY"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert for different proc files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CreateRuleR3005MaliciousFsMemoryInjection()
			failure := rule.ProcessEvent(tt.eventType, tt.event, nil)

			if tt.expectedAlert {
				assert.NotNil(t, failure, tt.description)
				if failure != nil {
					assert.Contains(t, failure.(*ruleenginev1.GenericRuleFailure).RuleAlert.RuleDescription,
						"Process memory injection attempt detected", "Alert description should mention process injection")
				}
			} else {
				assert.Nil(t, failure, tt.description)
			}
		})
	}
}

func TestIsProcMemPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"valid path", "/proc/1234/mem", true},
		{"invalid pid", "/proc/abc/mem", false},
		{"wrong file", "/proc/1234/maps", false},
		{"too short", "/proc/mem", false},
		{"too long", "/proc/1234/mem/extra", false},
		{"not proc", "/var/1234/mem", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isProcMemPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}
