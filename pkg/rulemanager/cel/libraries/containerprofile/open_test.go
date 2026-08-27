package containerprofile

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

// These two tests previously pinned the opposite contract — that Patterns must
// never contribute to suffix/prefix answers (CodeRabbit PR #43 review on
// open.go:79). That contract caused a permanent false positive: volatile paths are
// always stored as Patterns, so a correctly learned profile records the kubelet
// atomic-writer SA-token open as "/run/secrets/.../serviceaccount/⋯/token" and the
// helper answered "not opened", firing R0006 on every read. Issue #98.
//
// The stated rationale did not support the code it justified. It warned that
// strings.HasSuffix on a pattern "returns false and produces a false negative" —
// but skipping Patterns returns false too, so the blanket skip GUARANTEED the very
// false negative it was meant to avoid, for concrete-leaf patterns as well as
// wildcard-leaf ones.
//
// The corrected contract, pinned below:
//
//   - a pattern whose trailing text after the last collapse token ends with the
//     queried suffix DOES answer true — every concrete path it stands for ends
//     that way ("⋯/token" really does end with "/token");
//   - a pattern whose LEAF is a wildcard still answers false, which is exactly the
//     old behaviour, so scanning Patterns is never worse than skipping them;
//   - the same, mirrored, for prefixes against a pattern's concrete head.
//
// This also brings the Opens.All branch into agreement with the projected branch,
// where projection_apply.go already computes SuffixHits/PrefixHits over every raw
// entry including dynamic ones.

func TestWasPathOpenedWithSuffix_ConcreteLeafPatternMatches(t *testing.T) {
	pcp := &objectcache.ProjectedContainerProfile{
		Opens: objectcache.ProjectedField{
			All:      true,
			Values:   map[string]struct{}{"/var/log/concrete.log": {}},
			Patterns: []string{"/var/log/⋯/foo.log"},
		},
	}
	objCache := &mockObjectCacheForPattern{pcp: pcp}
	lib := &containerProfileLibrary{objectCache: objCache}

	// concrete Values entry still answers
	got := lib.wasPathOpenedWithSuffix(types.String("test-cid"), types.String(".log"))
	if b, _ := got.Value().(bool); !b {
		t.Fatalf("suffix '.log' against concrete /var/log/concrete.log: expected true, got %v", got)
	}

	// with Values emptied, the concrete-leaf pattern must now answer
	pcp.Opens.Values = map[string]struct{}{}
	got = lib.wasPathOpenedWithSuffix(types.String("test-cid"), types.String(".log"))
	if b, _ := got.Value().(bool); !b {
		t.Errorf("suffix '.log' against concrete-leaf pattern /var/log/⋯/foo.log: "+
			"expected true (its leaf really does end in .log), got %v", got)
	}

	// a wildcard LEAF still cannot answer — unchanged from the old behaviour
	pcp.Opens.Patterns = []string{"/var/log/pods/⋯"}
	got = lib.wasPathOpenedWithSuffix(types.String("test-cid"), types.String(".log"))
	if b, _ := got.Value().(bool); b {
		t.Errorf("suffix '.log' against wildcard-leaf pattern /var/log/pods/⋯: "+
			"expected false, got %v", got)
	}
}

func TestWasPathOpenedWithPrefix_ConcreteHeadPatternMatches(t *testing.T) {
	pcp := &objectcache.ProjectedContainerProfile{
		Opens: objectcache.ProjectedField{
			All:      true,
			Values:   map[string]struct{}{"/var/concrete/foo": {}},
			Patterns: []string{"/var/⋯/log/foo"},
		},
	}
	objCache := &mockObjectCacheForPattern{pcp: pcp}
	lib := &containerProfileLibrary{objectCache: objCache}

	got := lib.wasPathOpenedWithPrefix(types.String("test-cid"), types.String("/var/"))
	if b, _ := got.Value().(bool); !b {
		t.Fatalf("prefix '/var/' against concrete /var/concrete/foo: expected true, got %v", got)
	}

	// with Values emptied, the pattern's concrete head must answer
	pcp.Opens.Values = map[string]struct{}{}
	got = lib.wasPathOpenedWithPrefix(types.String("test-cid"), types.String("/var/"))
	if b, _ := got.Value().(bool); !b {
		t.Errorf("prefix '/var/' against pattern /var/⋯/log/foo: expected true "+
			"(the head before the collapse token is literal), got %v", got)
	}

	// a prefix reaching past the collapse token still cannot be answered
	got = lib.wasPathOpenedWithPrefix(types.String("test-cid"), types.String("/var/spool/"))
	if b, _ := got.Value().(bool); b {
		t.Errorf("prefix '/var/spool/' against pattern /var/⋯/log/foo: expected false, got %v", got)
	}
}

// mockObjectCacheForPattern returns a fixed ProjectedContainerProfile
// for any containerID; used only by the suffix/prefix pattern tests
// above to bypass the full RuleObjectCacheMock setup.
type mockObjectCacheForPattern struct {
	objectcache.ObjectCache
	pcp *objectcache.ProjectedContainerProfile
}

func (m *mockObjectCacheForPattern) ContainerProfileCache() objectcache.ContainerProfileCache {
	return &mockCPCForPattern{pcp: m.pcp}
}

type mockCPCForPattern struct {
	objectcache.ContainerProfileCache
	pcp *objectcache.ProjectedContainerProfile
}

func (m *mockCPCForPattern) GetProjectedContainerProfile(_ string) *objectcache.ProjectedContainerProfile {
	return m.pcp
}

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

	profile := &v1beta1.ContainerProfile{}
	profile.Spec = v1beta1.ContainerProfileSpec{
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
	}
	objCache.SetContainerProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		CP(&objCache, config.Config{}),
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
			ast, issues := env.Compile(`cp.was_path_opened(containerID, path)`)
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
			assert.Equal(t, tc.expectedResult, actualResult, "cp.was_path_opened result should match expected value")
		})
	}
}

func TestOpenNoProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		CP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile(`cp.was_path_opened(containerID, path)`)
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
	assert.False(t, actualResult, "cp.was_path_opened should return false when no profile is available")
}

func TestOpenCompilation(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		CP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	// Test that the function compiles correctly
	ast, issues := env.Compile(`cp.was_path_opened(containerID, path)`)
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

	profile := &v1beta1.ContainerProfile{}
	profile.Spec = v1beta1.ContainerProfileSpec{
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
	}
	objCache.SetContainerProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("suffix", cel.StringType),
		CP(&objCache, config.Config{}),
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
			ast, issues := env.Compile(`cp.was_path_opened_with_suffix(containerID, suffix)`)
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
			assert.Equal(t, tc.expectedResult, actualResult, "cp.was_path_opened_with_suffix result should match expected value")
		})
	}
}

func TestOpenWithSuffixNoProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("suffix", cel.StringType),
		CP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile(`cp.was_path_opened_with_suffix(containerID, suffix)`)
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
	assert.False(t, actualResult, "cp.was_path_opened_with_suffix should return false when no profile is available")
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

	profile := &v1beta1.ContainerProfile{}
	profile.Spec = v1beta1.ContainerProfileSpec{
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
	}
	objCache.SetContainerProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("prefix", cel.StringType),
		CP(&objCache, config.Config{}),
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
			ast, issues := env.Compile(`cp.was_path_opened_with_prefix(containerID, prefix)`)
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
			assert.Equal(t, tc.expectedResult, actualResult, "cp.was_path_opened_with_prefix result should match expected value")
		})
	}
}

func TestOpenWithPrefixNoProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("prefix", cel.StringType),
		CP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile(`cp.was_path_opened_with_prefix(containerID, prefix)`)
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
	assert.False(t, actualResult, "cp.was_path_opened_with_prefix should return false when no profile is available")
}

func TestOpenWithSuffixCompilation(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("suffix", cel.StringType),
		CP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	// Test that the function compiles correctly
	ast, issues := env.Compile(`cp.was_path_opened_with_suffix(containerID, suffix)`)
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
		CP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	// Test that the function compiles correctly
	ast, issues := env.Compile(`cp.was_path_opened_with_prefix(containerID, prefix)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	// Test that we can create a program
	_, err = env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}
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

	profile := &v1beta1.ContainerProfile{}
	profile.Spec = v1beta1.ContainerProfileSpec{
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
	}
	objCache.SetContainerProfile(profile)

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("flags", cel.ListType(cel.StringType)),
		CP(&objCache, config.Config{}),
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
			// v1 degradation: flags projection is out of scope; path-only matching.
			name:           "Path matches but flags don't match",
			containerID:    "test-container-id",
			path:           "/etc/passwd",
			flags:          []string{"O_WRONLY"},
			expectedResult: true,
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
			ast, issues := env.Compile(`cp.was_path_opened_with_flags(containerID, path, flags)`)
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
			assert.Equal(t, tc.expectedResult, actualResult, "cp.was_path_opened_with_flags result should match expected value")
		})
	}
}

func TestOpenWithFlagsNoProfile(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("flags", cel.ListType(cel.StringType)),
		CP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	ast, issues := env.Compile(`cp.was_path_opened_with_flags(containerID, path, flags)`)
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
	assert.False(t, actualResult, "cp.was_path_opened_with_flags should return false when no profile is available")
}

func TestOpenWithFlagsCompilation(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{}

	env, err := cel.NewEnv(
		cel.Variable("containerID", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("flags", cel.ListType(cel.StringType)),
		CP(&objCache, config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	// Test that the function compiles correctly
	ast, issues := env.Compile(`cp.was_path_opened_with_flags(containerID, path, flags)`)
	if issues != nil {
		t.Fatalf("failed to compile expression: %v", issues.Err())
	}

	// Test that we can create a program
	_, err = env.Program(ast)
	if err != nil {
		t.Fatalf("failed to create program: %v", err)
	}
}
