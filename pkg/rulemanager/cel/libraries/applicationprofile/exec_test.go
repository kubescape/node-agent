package applicationprofile

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestExecInProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{
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
				Path: "/bin/ls",
				Args: []string{"-la"},
			},
			{
				Path: "/usr/bin/curl",
				Args: []string{"https://example.com"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	testCases := []struct {
		name           string
		containerID    string
		path           string
		expectedResult bool
	}{
		{
			name:           "Path exists in profile",
			containerID:    "test-container-id",
			path:           "/bin/ls",
			expectedResult: true,
		},
		{
			name:           "Path does not exist in profile",
			containerID:    "test-container-id",
			path:           "/bin/nonexistent",
			expectedResult: false,
		},
		{
			name:           "Another path exists in profile",
			containerID:    "test-container-id",
			path:           "/usr/bin/curl",
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_executed(containerID, path)`)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}

			result, _, err := program.Eval(map[string]interface{}{
				"containerID": tc.containerID,
				"path":        tc.path,
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actualResult := result.Value().(bool)
			assert.Equal(t, tc.expectedResult, actualResult, "ap.was_executed result should match expected value")
		})
	}
}

func TestExecNoProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile(`ap.was_executed(containerID, path)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}

	result, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"path":        "/bin/ls",
	})
	if err != nil {
		t.Fatalf("failed to eval program: %v", err)
	}

	actualResult := result.Value().(bool)
	assert.False(t, actualResult, "ap.was_executed should return false when no profile is available")
}

func TestExecWithArgsInProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{
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
				Path: "/bin/ls",
				Args: []string{"-la", "/tmp"},
			},
			{
				Path: "/usr/bin/curl",
				Args: []string{"-X", "POST", "https://example.com"},
			},
			{
				Path: "/bin/echo",
				Args: []string{"hello", "world"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("args", cel.ListType(cel.StringType)),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	testCases := []struct {
		name           string
		containerID    string
		path           string
		args           []string
		expectedResult bool
	}{
		{
			name:           "Path and args match exactly",
			containerID:    "test-container-id",
			path:           "/bin/ls",
			args:           []string{"-la", "/tmp"},
			expectedResult: true,
		},
		{
			// Args are anchored — wrong arg mismatch must reject the exec.
			// Fork restores CompareExecArgs matching that upstream
			// projection-v1 had temporarily dropped.
			name:           "Path matches but args don't match",
			containerID:    "test-container-id",
			path:           "/bin/ls",
			args:           []string{"-la", "/home"},
			expectedResult: false,
		},
		{
			name:           "Path doesn't exist",
			containerID:    "test-container-id",
			path:           "/bin/nonexistent",
			args:           []string{"arg1", "arg2"},
			expectedResult: false,
		},
		{
			name:           "Complex args match",
			containerID:    "test-container-id",
			path:           "/usr/bin/curl",
			args:           []string{"-X", "POST", "https://example.com"},
			expectedResult: true,
		},
		{
			name:           "Simple args match",
			containerID:    "test-container-id",
			path:           "/bin/echo",
			args:           []string{"hello", "world"},
			expectedResult: true,
		},
		{
			// /bin/ls in the profile has Args: ["-la", "/tmp"]. An empty
			// runtime args list cannot satisfy a 2-arg anchored profile.
			// (Empty profile Args = "no argv constraint" still matches via
			// the back-compat branch; that's a separate case.)
			name:           "Empty args list",
			containerID:    "test-container-id",
			path:           "/bin/ls",
			args:           []string{},
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_executed_with_args(containerID, path, args)`)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}

			result, _, err := program.Eval(map[string]interface{}{
				"containerID": tc.containerID,
				"path":        tc.path,
				"args":        tc.args,
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actualResult := result.Value().(bool)
			assert.Equal(t, tc.expectedResult, actualResult, "ap.was_executed_with_args result should match expected value")
		})
	}
}

func TestExecWithArgsNoProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("args", cel.ListType(cel.StringType)),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile(`ap.was_executed_with_args(containerID, path, args)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}

	result, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"path":        "/bin/ls",
		"args":        []string{"-la", "/tmp"},
	})
	if err != nil {
		t.Fatalf("failed to eval program: %v", err)
	}

	actualResult := result.Value().(bool)
	assert.False(t, actualResult, "ap.was_executed_with_args should return false when no profile is available")
}

// TestExecWithArgsWildcardInProfile exercises wildcard tokens inside a
// user-defined ApplicationProfile's exec arg vector:
//
//	"⋯" (DynamicIdentifier)  — matches exactly one argument position.
//	"*" (WildcardIdentifier) — matches zero or more consecutive args.
//
// The runtime exec arg vector is matched against the profile via
// dynamicpathdetector.CompareExecArgs (added in
// k8sstormcenter/storage#23 — the matcher that this CEL function now
// routes through instead of slices.Compare).
func TestExecWithArgsWildcardInProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{
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
			// curl any URL: --user must be literal, value is one position.
			{
				Path: "/usr/bin/curl",
				Args: []string{"--user", "⋯"},
			},
			// sh -c with any trailing payload (zero or more args).
			{
				Path: "/bin/sh",
				Args: []string{"-c", "*"},
			},
			// ls -l in any directory — single trailing position.
			{
				Path: "/bin/ls",
				Args: []string{"-l", "⋯"},
			},
			// echo with any number of greeting words after a literal anchor.
			{
				Path: "/bin/echo",
				Args: []string{"hello", "*"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("args", cel.ListType(cel.StringType)),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	testCases := []struct {
		name           string
		path           string
		args           []string
		expectedResult bool
	}{
		// curl with --user, dynamic value
		{"curl --user alice — ⋯ matches one arg", "/usr/bin/curl", []string{"--user", "alice"}, true},
		{"curl --user alice bob — extra arg, ⋯ rejects", "/usr/bin/curl", []string{"--user", "alice", "bob"}, false},
		{"curl --user — missing value, ⋯ requires one arg", "/usr/bin/curl", []string{"--user"}, false},
		{"curl --pass alice — literal mismatch", "/usr/bin/curl", []string{"--pass", "alice"}, false},

		// sh -c with arbitrary trailing payload
		{"sh -c with single command", "/bin/sh", []string{"-c", "echo hi"}, true},
		{"sh -c with multi-token command", "/bin/sh", []string{"-c", "while", "true;", "do", "sleep", "1;", "done"}, true},
		{"sh -c with no trailing args (* matches zero)", "/bin/sh", []string{"-c"}, true},
		{"sh -x — wrong flag", "/bin/sh", []string{"-x", "echo hi"}, false},

		// ls -l in any directory
		{"ls -l /var/log", "/bin/ls", []string{"-l", "/var/log"}, true},
		{"ls -l with no directory (⋯ requires one)", "/bin/ls", []string{"-l"}, false},

		// echo hello *
		{"echo hello world from test", "/bin/echo", []string{"hello", "world", "from", "test"}, true},
		{"echo hello (no trailing args)", "/bin/echo", []string{"hello"}, true},
		{"echo goodbye world — wrong literal anchor", "/bin/echo", []string{"goodbye", "world"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_executed_with_args(containerID, path, args)`)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}

			result, _, err := program.Eval(map[string]interface{}{
				"containerID": "test-container-id",
				"path":        tc.path,
				"args":        tc.args,
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actualResult := result.Value().(bool)
			assert.Equal(t, tc.expectedResult, actualResult,
				"runtime args %v vs profile (one of curl/sh/ls/echo overlay): got %v want %v",
				tc.args, actualResult, tc.expectedResult)
		})
	}
}

func TestExecWithArgsCompilation(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("args", cel.ListType(cel.StringType)),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	// Test that the function compiles correctly
	ast, issues := env.Compile(`ap.was_executed_with_args(containerID, path, args)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	// Test that we can create a program
	_, err = env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}
}
