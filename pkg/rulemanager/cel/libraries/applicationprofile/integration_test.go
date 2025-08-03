package applicationprofile

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilevalidator"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestIntegrationWithAllFunctions(t *testing.T) {
	objCache := profilevalidator.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {
				{
					Name: "test-container",
				},
			},
		},
	})

	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Execs: []v1beta1.ExecCalls{
			{
				Path: "/bin/bash",
				Args: []string{"/bin/bash", "-c", "curl http://example.com"},
			},
			{
				Path: "/usr/bin/ls",
				Args: []string{"/usr/bin/ls", "-la"},
			},
		},
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/etc/passwd",
				Flags: []string{"O_RDONLY"},
			},
			{
				Path:  "/tmp/suspicious.txt",
				Flags: []string{"O_WRONLY", "O_CREAT"},
			},
		},
		Syscalls: []string{
			"open",
			"read",
			"write",
			"execve",
			"fork",
		},
		Capabilities: []string{
			"NET_ADMIN",
			"SYS_ADMIN",
			"SETUID",
		},
	})
	objCache.SetApplicationProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	testCases := []struct {
		name           string
		expression     string
		expectedResult bool
	}{
		{
			name:           "Check suspicious execution pattern",
			expression:     `ap.was_executed_with_args(containerID, "/bin/bash", ["/bin/bash", "-c", "curl http://example.com"])`,
			expectedResult: true,
		},
		{
			name:           "Check file access pattern",
			expression:     `ap.was_path_opened_with_flags(containerID, "/etc/passwd", ["O_RDONLY"])`,
			expectedResult: true,
		},
		{
			name:           "Check dangerous syscall usage",
			expression:     `ap.was_syscall_used(containerID, "execve")`,
			expectedResult: true,
		},
		{
			name:           "Check dangerous capability usage",
			expression:     `ap.was_capability_used(containerID, "SYS_ADMIN")`,
			expectedResult: true,
		},
		{
			name:           "Complex security check - suspicious behavior",
			expression:     `ap.was_executed_with_args(containerID, "/bin/bash", ["/bin/bash", "-c", "curl http://example.com"]) && ap.was_path_opened(containerID, "/etc/passwd") && ap.was_syscall_used(containerID, "execve")`,
			expectedResult: true,
		},
		{
			name:           "Complex security check - dangerous capabilities",
			expression:     `ap.was_capability_used(containerID, "NET_ADMIN") || ap.was_capability_used(containerID, "SYS_ADMIN")`,
			expectedResult: true,
		},
		{
			name:           "Check non-existent operations",
			expression:     `ap.was_executed(containerID, "/bin/nonexistent") || ap.was_syscall_used(containerID, "nonexistent_syscall")`,
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(tc.expression)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}

			result, _, err := program.Eval(map[string]interface{}{
				"containerID": "test-container-id",
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actualResult := result.Value().(bool)
			assert.Equal(t, tc.expectedResult, actualResult, "Expression result should match expected value for: %s", tc.expression)
		})
	}
}
