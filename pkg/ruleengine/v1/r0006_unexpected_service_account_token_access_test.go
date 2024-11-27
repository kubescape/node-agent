package ruleengine

import (
	"fmt"
	"testing"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
)

func createTestEvent0006(containerName, path string, flags []string) *events.OpenEvent {
	return &events.OpenEvent{
		Event: traceropentype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					K8s: eventtypes.K8sMetadata{
						BasicK8sMetadata: eventtypes.BasicK8sMetadata{
							ContainerName: containerName,
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

func createTestProfile0006(containerName string, openCalls []v1beta1.OpenCalls) *v1beta1.ApplicationProfile {
	return &v1beta1.ApplicationProfile{
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:  containerName,
					Opens: openCalls,
				},
			},
		},
	}
}

func TestR0006UnexpectedServiceAccountTokenMount(t *testing.T) {
	tests := []struct {
		name          string
		event         *events.OpenEvent
		profile       *v1beta1.ApplicationProfile
		expectFailure bool
	}{
		// Non-token path tests
		{
			name:          "non-token path access",
			event:         createTestEvent0006("test", "/test", []string{"O_RDONLY"}),
			expectFailure: false,
		},
		{
			name:          "path with similar prefix but not token path",
			event:         createTestEvent0006("test", "/run/secrets/kubernetes.io/other", []string{"O_RDONLY"}),
			expectFailure: false,
		},

		// Directory level whitelist tests
		{
			name:  "access allowed when directory is whitelisted - token",
			event: createTestEvent0006("test", "/run/secrets/kubernetes.io/serviceaccount/token", []string{"O_RDONLY"}),
			profile: createTestProfile0006("test", []v1beta1.OpenCalls{{
				Path:  "/run/secrets/kubernetes.io/serviceaccount/namespace",
				Flags: []string{"O_RDONLY"},
			}}),
			expectFailure: false, // Should pass because directory is whitelisted
		},
		{
			name:  "access allowed when directory is whitelisted - ca.crt",
			event: createTestEvent0006("test", "/run/secrets/kubernetes.io/serviceaccount/ca.crt", []string{"O_RDONLY"}),
			profile: createTestProfile0006("test", []v1beta1.OpenCalls{{
				Path:  "/run/secrets/kubernetes.io/serviceaccount/token",
				Flags: []string{"O_RDONLY"},
			}}),
			expectFailure: false, // Should pass because directory is whitelisted
		},
		{
			name:  "access is not allowed when directory is not whitelisted - namespace",
			event: createTestEvent0006("test", "/run/secrets/kubernetes.io/serviceaccount/namespace", []string{"O_RDONLY"}),
			profile: createTestProfile0006("test", []v1beta1.OpenCalls{{
				Path:  "home",
				Flags: []string{"O_RDONLY"},
			}}),
			expectFailure: true, // Should fail because directory is not whitelisted
		},

		// Tests with EKS paths and timestamps
		{
			name: "whitelisted eks token access with timestamps",
			event: createTestEvent0006("test",
				"/run/secrets/eks.amazonaws.com/serviceaccount/..2024_11_1111_24_34_58.850095521/token",
				[]string{"O_RDONLY"}),
			profile: createTestProfile0006("test", []v1beta1.OpenCalls{{
				Path:  "/run/secrets/eks.amazonaws.com/serviceaccount/..2024_11_21_04_30_58.850095521/namespace",
				Flags: []string{"O_RDONLY"},
			}}),
			expectFailure: false, // Should pass because normalized directory matches
		},
		// Tests with EKS paths and timestamps
		{
			name: "whitelisted eks token access with timestamps with compress",
			event: createTestEvent0006("test",
				"/run/secrets/eks.amazonaws.com/serviceaccount/..2024_11_1111_24_34_58.850095521/token",
				[]string{"O_RDONLY"}),
			profile: createTestProfile0006("test", []v1beta1.OpenCalls{{
				Path:  fmt.Sprintf("/run/secrets/eks.amazonaws.com/serviceaccount/%s/token", dynamicpathdetector.DynamicIdentifier),
				Flags: []string{"O_RDONLY"},
			}}),
			expectFailure: false, // Should pass because normalized directory matches
		},
		// Tests with k8s paths and timestamps
		{
			name: "non whitelisted k8s token access with timestamps",
			event: createTestEvent0006("test",
				"/run/secrets/kubernetes.io/serviceaccount/..2024_11_24_09_06_53.3676909075/token",
				[]string{"O_RDONLY"}),
			profile: createTestProfile0006("test", []v1beta1.OpenCalls{{
				Path:  "/run/secrets",
				Flags: []string{"O_RDONLY"},
			}}),
			expectFailure: true, // Should fail because normalized directory does not match
		},
		// Tests with k8s paths and timestamps
		{
			name: "non whitelisted k8s token access with timestamps",
			event: createTestEvent0006("test",
				"/run/secrets/kubernetes.io/serviceaccount/..2024_11_24_09_06_53.3676909075/token",
				[]string{"O_RDONLY"}),
			profile: createTestProfile0006("test", []v1beta1.OpenCalls{{
				Path:  "/",
				Flags: []string{"O_RDONLY"},
			}}),
			expectFailure: true, // Should fail because normalized directory does not match
		},

		// Different service account path variants
		{
			name:  "var/run path variant matches run path whitelist",
			event: createTestEvent0006("test", "/var/run/secrets/kubernetes.io/serviceaccount/token", []string{"O_RDONLY"}),
			profile: createTestProfile0006("test", []v1beta1.OpenCalls{{
				Path:  "/run/secrets/kubernetes.io/serviceaccount/namespace",
				Flags: []string{"O_RDONLY"},
			}}),
			expectFailure: true, // Should fail because different base path
		},

		// No whitelisting tests
		{
			name:  "unauthorized token access",
			event: createTestEvent0006("test", "/run/secrets/kubernetes.io/serviceaccount/token", []string{"O_RDONLY"}),
			profile: createTestProfile0006("test", []v1beta1.OpenCalls{{
				Path:  "/some/other/path",
				Flags: []string{"O_RDONLY"},
			}}),
			expectFailure: true,
		},

		// Container mismatch tests
		{
			name:  "different container name",
			event: createTestEvent0006("test2", "/run/secrets/kubernetes.io/serviceaccount/token", []string{"O_RDONLY"}),
			profile: createTestProfile0006("test", []v1beta1.OpenCalls{{
				Path:  "/run/secrets/kubernetes.io/serviceaccount/token",
				Flags: []string{"O_RDONLY"},
			}}),
			expectFailure: false, // No profile for the container
		},

		// Edge cases
		{
			name:          "no application profile",
			event:         createTestEvent0006("test", "/run/secrets/kubernetes.io/serviceaccount/token", []string{"O_RDONLY"}),
			profile:       nil,
			expectFailure: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := CreateRuleR0006UnexpectedServiceAccountTokenAccess()
			mockCache := &RuleObjectCacheMock{}

			if tt.profile != nil {
				mockCache.SetApplicationProfile(tt.profile)
			}

			result := r.ProcessEvent(utils.OpenEventType, tt.event, mockCache)

			if tt.expectFailure && result == nil {
				t.Error("Expected rule failure but got nil")
			}

			if !tt.expectFailure && result != nil {
				t.Errorf("Expected no failure but got: %v", result)
			}
		})
	}
}
