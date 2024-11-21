package ruleengine

import (
	"testing"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func createTestEvent(path string, flags []string) *events.OpenEvent {
	return &events.OpenEvent{
		Event: traceropentype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					K8s: eventtypes.K8sMetadata{
						BasicK8sMetadata: eventtypes.BasicK8sMetadata{
							ContainerName: "test",
						},
					},
				},
			},
			Path:     path,
			FullPath: path,
			Flags:    flags,
		},
	}
}

func createTestProfile(containerName string, paths []string, flags []string) *v1beta1.ApplicationProfile {
	opens := make([]v1beta1.OpenCalls, len(paths))
	for i, path := range paths {
		opens[i] = v1beta1.OpenCalls{
			Path:  path,
			Flags: flags,
		}
	}

	return &v1beta1.ApplicationProfile{
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:  containerName,
					Opens: opens,
				},
			},
		},
	}
}

func TestR0010UnexpectedSensitiveFileAccess(t *testing.T) {
	tests := []struct {
		name            string
		event           *events.OpenEvent
		profile         *v1beta1.ApplicationProfile
		additionalPaths []interface{}
		expectAlert     bool
		description     string
	}{
		{
			name:        "No application profile",
			event:       createTestEvent("/test", []string{"O_RDONLY"}),
			profile:     nil,
			expectAlert: false,
			description: "Should not alert when no application profile is present",
		},
		{
			name:        "Whitelisted non-sensitive file",
			event:       createTestEvent("/test", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/test"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert for whitelisted non-sensitive file",
		},
		{
			name:        "Non-whitelisted non-sensitive file",
			event:       createTestEvent("/var/test1", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/test"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert for non-whitelisted non-sensitive file",
		},
		{
			name:        "Whitelisted sensitive file",
			event:       createTestEvent("/etc/shadow", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/etc/shadow"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert for whitelisted sensitive file",
		},
		{
			name:        "Non-whitelisted sensitive file",
			event:       createTestEvent("/etc/shadow", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/test"}, []string{"O_RDONLY"}),
			expectAlert: true,
			description: "Should alert for non-whitelisted sensitive file",
		},
		{
			name:            "Additional sensitive path",
			event:           createTestEvent("/etc/custom-sensitive", []string{"O_RDONLY"}),
			profile:         createTestProfile("test", []string{"/test"}, []string{"O_RDONLY"}),
			additionalPaths: []interface{}{"/etc/custom-sensitive"},
			expectAlert:     true,
			description:     "Should alert for non-whitelisted file in additional sensitive paths",
		},
		{
			name:        "Wildcard path match",
			event:       createTestEvent("/etc/blabla", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/etc/\u22ef"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert when path matches wildcard pattern",
		},
		{
			name:        "Path traversal attempt",
			event:       createTestEvent("/etc/shadow/../passwd", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/test"}, []string{"O_RDONLY"}),
			expectAlert: true,
			description: "Should alert for path traversal attempts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CreateRuleR0010UnexpectedSensitiveFileAccess()
			if rule == nil {
				t.Fatal("Expected rule to not be nil")
			}

			objCache := &RuleObjectCacheMock{}
			if tt.profile != nil {
				objCache.SetApplicationProfile(tt.profile)
			}

			if tt.additionalPaths != nil {
				rule.SetParameters(map[string]interface{}{
					"additionalPaths": tt.additionalPaths,
				})
			}

			result := rule.ProcessEvent(utils.OpenEventType, tt.event, objCache)

			if tt.expectAlert && result == nil {
				t.Errorf("%s: expected alert but got none", tt.description)
			}
			if !tt.expectAlert && result != nil {
				t.Errorf("%s: expected no alert but got one", tt.description)
			}
		})
	}
}
