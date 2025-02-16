package hostrules

import (
	"testing"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestR3006SuspiciousLogCleaning_ProcessEvent(t *testing.T) {
	tests := []struct {
		name          string
		eventType     utils.EventType
		event         *events.OpenEvent
		expectedAlert bool
		description   string
	}{
		{
			name:      "should_alert_on_auth_log_truncate",
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
								ContainerID:        "test-container",
								ContainerImageName: "malicious-image",
							},
						},
					},
					Path:     "/var/log/auth.log",
					FullPath: "/var/log/auth.log",
					Flags:    []string{"O_TRUNC", "O_WRONLY"},
					Comm:     "suspicious-process",
					Pid:      1234,
				},
			},
			expectedAlert: true,
			description:   "Should alert when auth.log is truncated by non-trusted process",
		},
		{
			name:      "should_not_alert_trusted_image",
			eventType: utils.OpenEventType,
			event: &events.OpenEvent{
				Event: traceropentype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							K8s: eventtypes.K8sMetadata{
								BasicK8sMetadata: eventtypes.BasicK8sMetadata{
									ContainerName: "logrotate",
									PodName:       "logrotate-pod",
									Namespace:     "logging",
								},
							},
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID:        "logrotate-container",
								ContainerImageName: "logrotate:latest",
							},
						},
					},
					Path:     "/var/log/auth.log",
					FullPath: "/var/log/auth.log",
					Flags:    []string{"O_TRUNC", "O_WRONLY"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert when log is truncated by trusted logging process",
		},
		{
			name:      "should_not_alert_non_log_file",
			eventType: utils.OpenEventType,
			event: &events.OpenEvent{
				Event: traceropentype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID:        "test-container",
								ContainerImageName: "test-image",
							},
						},
					},
					Path:     "/var/log/random.txt",
					FullPath: "/var/log/random.txt",
					Flags:    []string{"O_TRUNC"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert when truncating non-monitored log file",
		},
		{
			name:      "should_not_alert_no_trunc",
			eventType: utils.OpenEventType,
			event: &events.OpenEvent{
				Event: traceropentype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID:        "test-container",
								ContainerImageName: "test-image",
							},
						},
					},
					Path:     "/var/log/auth.log",
					FullPath: "/var/log/auth.log",
					Flags:    []string{"O_RDONLY"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert when opening log file without O_TRUNC flag",
		},
		{
			name:      "should_not_alert_non_open_event",
			eventType: utils.ExecveEventType,
			event: &events.OpenEvent{
				Event: traceropentype.Event{
					Event: eventtypes.Event{
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								ContainerID:        "test-container",
								ContainerImageName: "test-image",
							},
						},
					},
					Path:     "/var/log/auth.log",
					FullPath: "/var/log/auth.log",
					Flags:    []string{"O_TRUNC"},
				},
			},
			expectedAlert: false,
			description:   "Should not alert for non-open event types",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CreateRuleR3006SuspiciousLogCleaning()
			failure := rule.ProcessEvent(tt.eventType, tt.event, nil)

			if tt.expectedAlert {
				assert.NotNil(t, failure, tt.description)
			} else {
				assert.Nil(t, failure, tt.description)
			}
		})
	}
}

func TestIsAccessLogFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "exact_match",
			path:     "/var/log/auth.log",
			expected: true,
		},
		{
			name:     "non_monitored_log",
			path:     "/var/log/other.log",
			expected: false,
		},
		{
			name:     "relative_path",
			path:     "var/log/auth.log",
			expected: false,
		},
		{
			name:     "path_traversal_attempt",
			path:     "../../../var/log/auth.log",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAccessLogFile(tt.path)
			assert.Equal(t, tt.expected, result, "isAccessLogFile(%s) = %v; want %v",
				tt.path, result, tt.expected)
		})
	}
}

func TestIsTrustedLoggingImage(t *testing.T) {
	tests := []struct {
		name      string
		imageName string
		expected  bool
	}{
		{
			name:      "exact_match",
			imageName: "logrotate",
			expected:  true,
		},
		{
			name:      "with_version",
			imageName: "logrotate:1.0",
			expected:  true,
		},
		{
			name:      "with_path",
			imageName: "logging/syslog-ng:latest",
			expected:  true,
		},
		{
			name:      "untrusted_image",
			imageName: "nginx:latest",
			expected:  false,
		},
		{
			name:      "empty_string",
			imageName: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTrustedLoggingImage(tt.imageName)
			assert.Equal(t, tt.expected, result, "isTrustedLoggingImage(%s) = %v; want %v",
				tt.imageName, result, tt.expected)
		})
	}
}
