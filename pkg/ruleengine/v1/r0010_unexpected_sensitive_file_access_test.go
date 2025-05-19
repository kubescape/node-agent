package ruleengine

import (
	"testing"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
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
			event:       createTestEvent("/etc/shadow/../shadow", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/test"}, []string{"O_RDONLY"}),
			expectAlert: true,
			description: "Should alert for path traversal attempts",
		},
		// Dynamic path matching tests
		{
			name:        "Dynamic directory match",
			event:       createTestEvent("/var/log/2024_01_01/app.log", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/var/log/" + dynamicpathdetector.DynamicIdentifier + "/app.log"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert when path matches dynamic pattern",
		},
		{
			name:        "Dynamic multi-segment match",
			event:       createTestEvent("/var/log/2024/01/01/app.log", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/var/log/" + dynamicpathdetector.DynamicIdentifier + "/" + dynamicpathdetector.DynamicIdentifier + "/" + dynamicpathdetector.DynamicIdentifier + "/app.log"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert when path matches multiple dynamic segments",
		},
		{
			name:        "Dynamic prefix match",
			event:       createTestEvent("/data/customer1/config.json", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/" + dynamicpathdetector.DynamicIdentifier + "/customer1/config.json"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert when path matches dynamic prefix",
		},
		{
			name:        "Dynamic suffix match",
			event:       createTestEvent("/etc/config/v1.2.3/settings.yaml", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/etc/config/" + dynamicpathdetector.DynamicIdentifier + "/settings.yaml"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert when path matches dynamic suffix",
		},
		{
			name:        "Dynamic timestamp directory match",
			event:       createTestEvent("/var/log/pods/2024_01_01_12_00_00/container.log", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/var/log/pods/" + dynamicpathdetector.DynamicIdentifier + "/container.log"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert when timestamp directory matches dynamic pattern",
		},
		{
			name:        "Dynamic service account token path",
			event:       createTestEvent("/run/secrets/kubernetes.io/serviceaccount/..2024_01_01_12_00_00.123456789/token", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/run/secrets/kubernetes.io/serviceaccount/" + dynamicpathdetector.DynamicIdentifier + "/token"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert when service account token path matches dynamic pattern",
		},
		{
			name:            "Sensitive file with dynamic path not whitelisted",
			event:           createTestEvent("/etc/kubernetes/..2024_01_01/secret.yaml", []string{"O_RDONLY"}),
			profile:         createTestProfile("test", []string{"/var/log/" + dynamicpathdetector.DynamicIdentifier + "/app.log"}, []string{"O_RDONLY"}),
			additionalPaths: []interface{}{"/etc/kubernetes"},
			expectAlert:     true,
			description:     "Should alert when sensitive file with timestamp is not whitelisted",
		},
		{
			name:  "Multiple whitelisted dynamic paths",
			event: createTestEvent("/var/log/2024_01_01/app.log", []string{"O_RDONLY"}),
			profile: createTestProfile("test",
				[]string{
					"/tmp/" + dynamicpathdetector.DynamicIdentifier + "/test.log",
					"/var/log/" + dynamicpathdetector.DynamicIdentifier + "/app.log",
				},
				[]string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert when path matches one of multiple dynamic patterns",
		},
		{
			name:        "Mixed static and dynamic segments",
			event:       createTestEvent("/data/users/john/2024_01_01/profile.json", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/data/users/john/" + dynamicpathdetector.DynamicIdentifier + "/profile.json"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert when static segments match and dynamic segment matches timestamp",
		},
		// {
		// 	name:        "Double slashes in path",
		// 	event:       createTestEvent("/etc//shadow", []string{"O_RDONLY"}),
		// 	profile:     createTestProfile("test", []string{"/etc/shadow"}, []string{"O_RDONLY"}),
		// 	expectAlert: false,
		// 	description: "Should normalize paths with double slashes",
		// },
		{
			name:        "Trailing slash differences",
			event:       createTestEvent("/etc/kubernetes/", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/etc/kubernetes"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should handle trailing slash differences",
		},
		{
			name:        "Partial path segment match",
			event:       createTestEvent("/etc/kubernetes-staging/secret", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/etc/kubernetes"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should not alert when path merely starts with a sensitive path string",
		},
		{
			name:  "Complex dynamic pattern combination",
			event: createTestEvent("/var/log/2024/01/pod-123/container-456/app.log", []string{"O_RDONLY"}),
			profile: createTestProfile("test", []string{
				"/var/log/" + dynamicpathdetector.DynamicIdentifier + "/" +
					dynamicpathdetector.DynamicIdentifier + "/pod-" +
					dynamicpathdetector.DynamicIdentifier + "/container-" +
					dynamicpathdetector.DynamicIdentifier + "/app.log"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should handle complex combinations of dynamic patterns",
		},
		{
			name:        "Empty path handling",
			event:       createTestEvent("", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/test"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should handle empty paths gracefully",
		},
		{
			name:        "Special characters in path",
			event:       createTestEvent("/etc/conf!g#file", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/etc/conf!g#file"}, []string{"O_RDONLY"}),
			expectAlert: false,
			description: "Should handle special characters in paths",
		},
		{
			name:        "Relative path with dots",
			event:       createTestEvent("./etc/shadow", []string{"O_RDONLY"}),
			profile:     createTestProfile("test", []string{"/etc/shadow"}, []string{"O_RDONLY"}),
			expectAlert: true,
			description: "Should handle relative paths correctly",
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

			result := ProcessRuleEvaluationTest(rule, utils.OpenEventType, tt.event, objCache)

			if tt.expectAlert && result == nil {
				t.Errorf("%s: expected alert but got none", tt.description)
			}
			if !tt.expectAlert && result != nil {
				t.Errorf("%s: expected no alert but got one", tt.description)
			}
		})
	}
}
