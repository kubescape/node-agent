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

func TestR3004DockerSocketAccess_ProcessEvent(t *testing.T) {
	tests := []struct {
		name          string
		eventType     utils.EventType
		event         *events.OpenEvent
		expectedAlert bool
		description   string
	}{
		{
			name:      "should_alert_on_docker_socket_access",
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
					Path:     "/var/run/docker.sock",
					FullPath: "/var/run/docker.sock",
					Flags:    []string{"O_RDWR"},
				},
			},
			expectedAlert: true,
			description:   "Should alert when Docker socket is accessed from non-allowed namespace",
		},
		{
			name:      "should_not_alert_in_allowed_namespace",
			eventType: utils.OpenEventType,
			event: &events.OpenEvent{
				Event: traceropentype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "jenkins-builder",
									PodName:       "jenkins-build-123",
									Namespace:     "ci",
								},
							},
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID: "test-container",
							},
						},
					},
					Path:     "/var/run/docker.sock",
					FullPath: "/var/run/docker.sock",
					Flags:    []string{"O_RDWR"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert when access is from allowed namespace",
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
					Path:     "/var/run/docker.sock",
					FullPath: "/var/run/docker.sock",
					Flags:    []string{"O_RDWR"},
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
					Path:     "/var/run/other.sock",
					FullPath: "/var/run/other.sock",
					Flags:    []string{"O_RDWR"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert when accessing a different socket file",
		},
		{
			name:      "should_not_alert_on_non_open_event",
			eventType: utils.ExecveEventType,
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
					Path:     "/var/run/docker.sock",
					FullPath: "/var/run/docker.sock",
					Flags:    []string{"O_RDWR"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert for non-open event types",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CreateRuleR3004DockerSocketAccess()
			failure := rule.ProcessEvent(tt.eventType, tt.event, nil)

			if tt.expectedAlert {
				assert.NotNil(t, failure, tt.description)
				if failure != nil {
					// Verify the alert contains expected docker socket information
					assert.Contains(t, failure.(*ruleenginev1.GenericRuleFailure).RuleAlert.RuleDescription,
						"docker.sock", "Alert description should mention docker socket")
				}
			} else {
				assert.Nil(t, failure, tt.description)
			}
		})
	}
}
