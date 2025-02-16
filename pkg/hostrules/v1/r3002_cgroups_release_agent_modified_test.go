package hostrules

import (
	"testing"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestR3002CGroupsReleaseAgent_ProcessEvent(t *testing.T) {
	tests := []struct {
		name          string
		eventType     utils.EventType
		event         *events.OpenEvent
		expectedAlert bool
		description   string
	}{
		{
			name:      "should_alert_on_write_to_release_agent",
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
							Runtime: eventtypes.BasicRuntimeMetadata{ContainerID: "test"},
						},
					},
					Path:     "/sys/../sys/fs/cgroup/release_agent",
					FullPath: "/sys/../sys/fs/cgroup/release_agent",
					Flags:    []string{"O_WRONLY"},
				},
			},
			expectedAlert: true,
			description:   "Should alert when release_agent file is opened with write permissions",
		},
		{
			name:      "should_alert_on_rdwr_to_release_agent",
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
					Path:     "/sys/fs/cgroup/memory/release_agent",
					FullPath: "/sys/fs/cgroup/memory/release_agent",
					Flags:    []string{"O_RDWR"},
				},
			},
			expectedAlert: true,
			description:   "Should alert when release_agent file is opened with read-write permissions",
		},
		{
			name:      "should_not_alert_on_read_only_access",
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
					Path:     "/sys/fs/cgroup/memory/release_agent",
					FullPath: "/sys/fs/cgroup/memory/release_agent",
					Flags:    []string{"O_RDONLY"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert when release_agent file is opened with read-only permissions",
		},
		{
			name:      "should_not_alert_on_non_container_access",
			eventType: utils.OpenEventType,
			event: &events.OpenEvent{
				Event: traceropentype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "",
									PodName:       "",
									Namespace:     "",
								},
							},
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID: "",
							},
						},
					},
					Path:     "/sys/fs/cgroup/memory/release_agent",
					FullPath: "/sys/fs/cgroup/memory/release_agent",
					Flags:    []string{"O_WRONLY"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert when access is from outside a container",
		},
		{
			name:      "should_not_alert_on_different_path",
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
					Path:     "/sys/fs/cgroup/memory/other_file",
					FullPath: "/sys/fs/cgroup/memory/other_file",
					Flags:    []string{"O_WRONLY"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert when accessing a different file in cgroups directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CreateRuleR3002CGroupsReleaseAgent()
			failure := rule.ProcessEvent(tt.eventType, tt.event, nil)

			if tt.expectedAlert {
				assert.NotNil(t, failure, tt.description)
			} else {
				assert.Nil(t, failure, tt.description)
			}
		})
	}
}
