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

func TestOpenInProfile(t *testing.T) {
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
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/etc/passwd",
				Flags: []string{"O_RDONLY"},
			},
			{
				Path:  "/tmp/test.txt",
				Flags: []string{"O_WRONLY", "O_CREAT"},
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
			path:           "/etc/passwd",
			expectedResult: true,
		},
		{
			name:           "Path does not exist in profile",
			containerID:    "test-container-id",
			path:           "/etc/nonexistent",
			expectedResult: false,
		},
		{
			name:           "Another path exists in profile",
			containerID:    "test-container-id",
			path:           "/tmp/test.txt",
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_path_opened(containerID, path)`)
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
			assert.Equal(t, tc.expectedResult, actualResult, "ap.was_path_opened result should match expected value")
		})
	}
}

func TestOpenWithWildcardProfile(t *testing.T) {
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

	// Profile with collapsed wildcard paths (as produced by storage's path analyzer)
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/",
				Flags: []string{"O_RDONLY"},
			},
			{
				Path:  "/*",
				Flags: []string{"O_CLOEXEC", "O_RDONLY", "O_RDWR", "O_NONBLOCK"},
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
		path           string
		expectedResult bool
	}{
		{
			name:           "Root path matches /",
			path:           "/",
			expectedResult: true,
		},
		{
			name:           "Wildcard /* matches /lib/x86_64-linux-gnu/libc-2.31.so",
			path:           "/lib/x86_64-linux-gnu/libc-2.31.so",
			expectedResult: true,
		},
		{
			name:           "Wildcard /* matches /proc/49/mountinfo",
			path:           "/proc/49/mountinfo",
			expectedResult: true,
		},
		{
			name:           "Wildcard /* matches /sys/fs/cgroup/cpu.max",
			path:           "/sys/fs/cgroup/cpu.max",
			expectedResult: true,
		},
		{
			name:           "Wildcard /* matches /etc/apache2/apache2.conf",
			path:           "/etc/apache2/apache2.conf",
			expectedResult: true,
		},
		{
			name:           "Wildcard /* matches single-level /tmp",
			path:           "/tmp",
			expectedResult: true,
		},
		{
			name:           "Wildcard /* matches deep path",
			path:           "/usr/share/zoneinfo/UTC",
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_path_opened(containerID, path)`)
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
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actualResult := result.Value().(bool)
			assert.Equal(t, tc.expectedResult, actualResult, "ap.was_path_opened result should match expected value")
		})
	}
}

func TestOpenWithDynamicIdentifierProfile(t *testing.T) {
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

	// Profile with ⋯ (single-segment dynamic) and * (multi-segment wildcard)
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/proc/\u22ef/mountinfo",
				Flags: []string{"O_RDONLY"},
			},
			{
				Path:  "/api/*/data",
				Flags: []string{"O_RDONLY"},
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
		path           string
		expectedResult bool
	}{
		{
			name:           "Dynamic ⋯ matches /proc/1/mountinfo",
			path:           "/proc/1/mountinfo",
			expectedResult: true,
		},
		{
			name:           "Dynamic ⋯ matches /proc/999/mountinfo",
			path:           "/proc/999/mountinfo",
			expectedResult: true,
		},
		{
			name:           "Dynamic ⋯ does NOT match /proc/1/2/mountinfo (two segments)",
			path:           "/proc/1/2/mountinfo",
			expectedResult: false,
		},
		{
			name:           "Wildcard * matches /api/v1/users/123/data",
			path:           "/api/v1/users/123/data",
			expectedResult: true,
		},
		{
			name:           "Wildcard * matches /api/data (zero intermediate segments)",
			path:           "/api/data",
			expectedResult: true,
		},
		{
			name:           "Path not in profile at all",
			path:           "/etc/passwd",
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_path_opened(containerID, path)`)
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
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actualResult := result.Value().(bool)
			assert.Equal(t, tc.expectedResult, actualResult, "ap.was_path_opened result should match expected value")
		})
	}
}

func TestOpenNoProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile(`ap.was_path_opened(containerID, path)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}

	result, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"path":        "/etc/passwd",
	})
	if err != nil {
		t.Fatalf("failed to eval program: %v", err)
	}

	actualResult := result.Value().(bool)
	assert.False(t, actualResult, "ap.was_path_opened should return false when no profile is available")
}

func TestOpenWithFlagsInProfile(t *testing.T) {
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
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/etc/passwd",
				Flags: []string{"O_RDONLY"},
			},
			{
				Path:  "/tmp/test.txt",
				Flags: []string{"O_WRONLY", "O_CREAT"},
			},
			{
				Path:  "/var/log/app.log",
				Flags: []string{"O_RDWR", "O_APPEND"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("flags", cel.ListType(cel.StringType)),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	testCases := []struct {
		name           string
		containerID    string
		path           string
		flags          []string
		expectedResult bool
	}{
		{
			name:           "Path and flags match exactly",
			containerID:    "test-container-id",
			path:           "/etc/passwd",
			flags:          []string{"O_RDONLY"},
			expectedResult: true,
		},
		{
			name:           "Path matches but flags don't match",
			containerID:    "test-container-id",
			path:           "/etc/passwd",
			flags:          []string{"O_WRONLY"},
			expectedResult: false,
		},
		{
			name:           "Path doesn't exist",
			containerID:    "test-container-id",
			path:           "/etc/nonexistent",
			flags:          []string{"O_RDONLY"},
			expectedResult: false,
		},
		{
			name:           "Multiple flags match",
			containerID:    "test-container-id",
			path:           "/tmp/test.txt",
			flags:          []string{"O_WRONLY", "O_CREAT"},
			expectedResult: true,
		},
		{
			name:           "Multiple flags in different order",
			containerID:    "test-container-id",
			path:           "/tmp/test.txt",
			flags:          []string{"O_CREAT", "O_WRONLY"},
			expectedResult: true,
		},
		{
			name:           "Partial flags match",
			containerID:    "test-container-id",
			path:           "/tmp/test.txt",
			flags:          []string{"O_WRONLY"},
			expectedResult: true,
		},
		{
			name:           "Empty flags list",
			containerID:    "test-container-id",
			path:           "/etc/passwd",
			flags:          []string{},
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_path_opened_with_flags(containerID, path, flags)`)
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
				"flags":       tc.flags,
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actualResult := result.Value().(bool)
			assert.Equal(t, tc.expectedResult, actualResult, "ap.was_path_opened_with_flags result should match expected value")
		})
	}
}

func TestOpenWithFlagsNoProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("flags", cel.ListType(cel.StringType)),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile(`ap.was_path_opened_with_flags(containerID, path, flags)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}

	result, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"path":        "/etc/passwd",
		"flags":       []string{"O_RDONLY"},
	})
	if err != nil {
		t.Fatalf("failed to eval program: %v", err)
	}

	actualResult := result.Value().(bool)
	assert.False(t, actualResult, "ap.was_path_opened_with_flags should return false when no profile is available")
}

func TestOpenWithFlagsCompilation(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("flags", cel.ListType(cel.StringType)),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	// Test that the function compiles correctly
	ast, issues := env.Compile(`ap.was_path_opened_with_flags(containerID, path, flags)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	// Test that we can create a program
	_, err = env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}
}

func TestOpenCompilation(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	// Test that the function compiles correctly
	ast, issues := env.Compile(`ap.was_path_opened(containerID, path)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	// Test that we can create a program
	_, err = env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}
}

func TestOpenWithSuffixInProfile(t *testing.T) {
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
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/etc/passwd",
				Flags: []string{"O_RDONLY"},
			},
			{
				Path:  "/tmp/test.txt",
				Flags: []string{"O_WRONLY", "O_CREAT"},
			},
			{
				Path:  "/var/log/app.log",
				Flags: []string{"O_RDWR", "O_APPEND"},
			},
			{
				Path:  "/home/user/config.json",
				Flags: []string{"O_RDONLY"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("suffix", cel.StringType),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	testCases := []struct {
		name           string
		containerID    string
		suffix         string
		expectedResult bool
	}{
		{
			name:           "Suffix matches .txt file",
			containerID:    "test-container-id",
			suffix:         ".txt",
			expectedResult: true,
		},
		{
			name:           "Suffix matches .log file",
			containerID:    "test-container-id",
			suffix:         ".log",
			expectedResult: true,
		},
		{
			name:           "Suffix matches .json file",
			containerID:    "test-container-id",
			suffix:         ".json",
			expectedResult: true,
		},
		{
			name:           "Suffix doesn't match any file",
			containerID:    "test-container-id",
			suffix:         ".xml",
			expectedResult: false,
		},
		{
			name:           "Empty suffix",
			containerID:    "test-container-id",
			suffix:         "",
			expectedResult: true, // All paths end with empty string
		},
		{
			name:           "Suffix matches exact path",
			containerID:    "test-container-id",
			suffix:         "/etc/passwd",
			expectedResult: true,
		},
		{
			name:           "Partial suffix doesn't match",
			containerID:    "test-container-id",
			suffix:         "xyz",
			expectedResult: false, // None of the paths end with "xyz"
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_path_opened_with_suffix(containerID, suffix)`)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}

			result, _, err := program.Eval(map[string]interface{}{
				"containerID": tc.containerID,
				"suffix":      tc.suffix,
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actualResult := result.Value().(bool)
			assert.Equal(t, tc.expectedResult, actualResult, "ap.was_path_opened_with_suffix result should match expected value")
		})
	}
}

func TestOpenWithSuffixNoProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("suffix", cel.StringType),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile(`ap.was_path_opened_with_suffix(containerID, suffix)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}

	result, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"suffix":      ".txt",
	})
	if err != nil {
		t.Fatalf("failed to eval program: %v", err)
	}

	actualResult := result.Value().(bool)
	assert.False(t, actualResult, "ap.was_path_opened_with_suffix should return false when no profile is available")
}

func TestOpenWithPrefixInProfile(t *testing.T) {
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
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/etc/passwd",
				Flags: []string{"O_RDONLY"},
			},
			{
				Path:  "/tmp/test.txt",
				Flags: []string{"O_WRONLY", "O_CREAT"},
			},
			{
				Path:  "/var/log/app.log",
				Flags: []string{"O_RDWR", "O_APPEND"},
			},
			{
				Path:  "/home/user/config.json",
				Flags: []string{"O_RDONLY"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("prefix", cel.StringType),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	testCases := []struct {
		name           string
		containerID    string
		prefix         string
		expectedResult bool
	}{
		{
			name:           "Prefix matches /etc",
			containerID:    "test-container-id",
			prefix:         "/etc",
			expectedResult: true,
		},
		{
			name:           "Prefix matches /tmp",
			containerID:    "test-container-id",
			prefix:         "/tmp",
			expectedResult: true,
		},
		{
			name:           "Prefix matches /var",
			containerID:    "test-container-id",
			prefix:         "/var",
			expectedResult: true,
		},
		{
			name:           "Prefix matches /home",
			containerID:    "test-container-id",
			prefix:         "/home",
			expectedResult: true,
		},
		{
			name:           "Prefix doesn't match any path",
			containerID:    "test-container-id",
			prefix:         "/usr",
			expectedResult: false,
		},
		{
			name:           "Empty prefix",
			containerID:    "test-container-id",
			prefix:         "",
			expectedResult: true, // All paths start with empty string
		},
		{
			name:           "Prefix matches exact path",
			containerID:    "test-container-id",
			prefix:         "/etc/passwd",
			expectedResult: true,
		},
		{
			name:           "Partial prefix doesn't match",
			containerID:    "test-container-id",
			prefix:         "etc",
			expectedResult: false, // /etc/passwd doesn't start with "etc"
		},
		{
			name:           "Prefix with trailing slash",
			containerID:    "test-container-id",
			prefix:         "/etc/",
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_path_opened_with_prefix(containerID, prefix)`)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}

			result, _, err := program.Eval(map[string]interface{}{
				"containerID": tc.containerID,
				"prefix":      tc.prefix,
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actualResult := result.Value().(bool)
			assert.Equal(t, tc.expectedResult, actualResult, "ap.was_path_opened_with_prefix result should match expected value")
		})
	}
}

func TestOpenWithPrefixNoProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("prefix", cel.StringType),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile(`ap.was_path_opened_with_prefix(containerID, prefix)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}

	result, _, err := program.Eval(map[string]interface{}{
		"containerID": "test-container-id",
		"prefix":      "/etc",
	})
	if err != nil {
		t.Fatalf("failed to eval program: %v", err)
	}

	actualResult := result.Value().(bool)
	assert.False(t, actualResult, "ap.was_path_opened_with_prefix should return false when no profile is available")
}

func TestOpenWithSuffixCompilation(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("suffix", cel.StringType),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	// Test that the function compiles correctly
	ast, issues := env.Compile(`ap.was_path_opened_with_suffix(containerID, suffix)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	// Test that we can create a program
	_, err = env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}
}

func TestOpenWithPrefixCompilation(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("prefix", cel.StringType),
		AP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	// Test that the function compiles correctly
	ast, issues := env.Compile(`ap.was_path_opened_with_prefix(containerID, prefix)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	// Test that we can create a program
	_, err = env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}
}
