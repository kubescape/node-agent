package applicationprofile

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

// TestWasPathOpenedWithSuffix_PatternsNotScanned pins the contract from
// the CodeRabbit PR #43 review on open.go:79 (Major). Wildcard-shaped
// entries in cp.Opens.Patterns MUST NOT contribute to suffix/prefix
// answers — their literal text answers the wrong question. A retained
// pattern "/var/log/pods/*/volumes/...." doesn't END with "foo.log"
// even though the concrete open it stands in for might. Only concrete
// paths in cp.Opens.Values are valid sources of suffix/prefix truth in
// pass-through (Opens.All=true) mode.
//
// In projection-active mode (Opens.All=false), the rule manager
// precomputes Opens.SuffixHits / PrefixHits from the spec, which is
// the correct mechanism — those are exercised in
// TestOpenWithSuffixInProfile / TestOpenWithPrefixInProfile.
//
// These tests pin Matthias's upstream PR #811 review contract:
//
//   Patterns ARE scanned when Opens.All == true, but with a NARROWER
//   fallback than text-level strings.HasSuffix/HasPrefix:
//
//   * Pattern with a concrete tail/head (text after/before the last/first
//     wildcard segment): match via HasSuffix/HasPrefix on the concrete
//     piece — every realisation has that text textually.
//   * Pattern ending/starting with a wildcard segment: be PERMISSIVE
//     (return true). The concrete realisations could match ANY
//     suffix/prefix; refusing would silently regress rules that omit
//     profileDataRequired.opens (Matthias's "we still need a narrower
//     fallback here instead of ignoring Patterns entirely").
//
// Pre-PR-#811 (CR's HasSuffix-on-Patterns concern) the matcher SKIPPED
// Patterns entirely. That made wildcard-only profiles silently fail
// suffix/prefix queries — the regression Matthias's review reverses.
func TestWasPathOpenedWithSuffix_PatternsScannedWithConcreteTail(t *testing.T) {
	pcp := &objectcache.ProjectedContainerProfile{
		Opens: objectcache.ProjectedField{
			All:      true,
			Values:   map[string]struct{}{"/var/log/concrete.log": {}},
			Patterns: []string{"/var/log/⋯/foo.log"},
		},
	}
	objCache := &mockObjectCacheForPattern{pcp: pcp}
	lib := &apLibrary{objectCache: objCache}

	// 1) Concrete in Values: returns true via Values scan.
	got := lib.wasPathOpenedWithSuffix(types.String("test-cid"), types.String(".log"))
	if b, _ := got.Value().(bool); !b {
		t.Fatalf("suffix '.log' against concrete /var/log/concrete.log: expected true, got %v", got)
	}

	// 2) Strip Values; only the wildcard Pattern remains. The pattern's
	//    concrete tail (text after the last wildcard segment) is
	//    "/foo.log" which DOES end with ".log" → expect true.
	pcp.Opens.Values = map[string]struct{}{}
	got = lib.wasPathOpenedWithSuffix(types.String("test-cid"), types.String(".log"))
	if b, _ := got.Value().(bool); !b {
		t.Errorf("suffix '.log' against pattern /var/log/⋯/foo.log: "+
			"expected true (concrete tail '/foo.log' has suffix '.log'), got %v", got)
	}

	// 3) Same pattern, query suffix that DOESN'T match the concrete tail.
	got = lib.wasPathOpenedWithSuffix(types.String("test-cid"), types.String(".txt"))
	if b, _ := got.Value().(bool); b {
		t.Errorf("suffix '.txt' against pattern /var/log/⋯/foo.log: "+
			"expected false (concrete tail '/foo.log' doesn't have suffix '.txt'), got %v", got)
	}
}

// TestWasPathOpenedWithSuffix_PatternWildcardTail_Permissive pins the
// permissive arm of Matthias's contract: a pattern ending in a wildcard
// segment can match ANY suffix because its concrete realisations are
// unconstrained at the tail.
func TestWasPathOpenedWithSuffix_PatternWildcardTail_Permissive(t *testing.T) {
	pcp := &objectcache.ProjectedContainerProfile{
		Opens: objectcache.ProjectedField{
			All:      true,
			Values:   map[string]struct{}{},
			Patterns: []string{"/var/log/pods/*"},
		},
	}
	objCache := &mockObjectCacheForPattern{pcp: pcp}
	lib := &apLibrary{objectCache: objCache}

	for _, suffix := range []string{".log", "/foo.log", "kube-system"} {
		got := lib.wasPathOpenedWithSuffix(types.String("test-cid"), types.String(suffix))
		if b, _ := got.Value().(bool); !b {
			t.Errorf("suffix %q against pattern /var/log/pods/*: "+
				"expected true (permissive — wildcard tail), got %v", suffix, got)
		}
	}
}

// TestWasPathOpenedWithPrefix_PatternsScannedWithConcreteHead mirrors
// the suffix test for the prefix path.
func TestWasPathOpenedWithPrefix_PatternsScannedWithConcreteHead(t *testing.T) {
	pcp := &objectcache.ProjectedContainerProfile{
		Opens: objectcache.ProjectedField{
			All:      true,
			Values:   map[string]struct{}{"/var/concrete/foo": {}},
			Patterns: []string{"/var/⋯/log/foo"},
		},
	}
	objCache := &mockObjectCacheForPattern{pcp: pcp}
	lib := &apLibrary{objectCache: objCache}

	got := lib.wasPathOpenedWithPrefix(types.String("test-cid"), types.String("/var/"))
	if b, _ := got.Value().(bool); !b {
		t.Fatalf("prefix '/var/' against concrete /var/concrete/foo: expected true, got %v", got)
	}

	// Strip Values; the pattern's concrete head is "/var/" which DOES
	// start with the queried prefix "/var/" → expect true.
	pcp.Opens.Values = map[string]struct{}{}
	got = lib.wasPathOpenedWithPrefix(types.String("test-cid"), types.String("/var/"))
	if b, _ := got.Value().(bool); !b {
		t.Errorf("prefix '/var/' against pattern /var/⋯/log/foo: "+
			"expected true (concrete head '/var/' starts with '/var/'), got %v", got)
	}

	// Query prefix that doesn't match the concrete head.
	got = lib.wasPathOpenedWithPrefix(types.String("test-cid"), types.String("/etc/"))
	if b, _ := got.Value().(bool); b {
		t.Errorf("prefix '/etc/' against pattern /var/⋯/log/foo: "+
			"expected false (concrete head '/var/' doesn't start with '/etc/'), got %v", got)
	}
}

// TestWasPathOpenedWithPrefix_PatternWildcardHead_Permissive pins the
// permissive arm of the prefix path.
func TestWasPathOpenedWithPrefix_PatternWildcardHead_Permissive(t *testing.T) {
	pcp := &objectcache.ProjectedContainerProfile{
		Opens: objectcache.ProjectedField{
			All:      true,
			Values:   map[string]struct{}{},
			Patterns: []string{"*/run"},
		},
	}
	objCache := &mockObjectCacheForPattern{pcp: pcp}
	lib := &apLibrary{objectCache: objCache}

	for _, prefix := range []string{"/var/lib", "/etc", "/anything"} {
		got := lib.wasPathOpenedWithPrefix(types.String("test-cid"), types.String(prefix))
		if b, _ := got.Value().(bool); !b {
			t.Errorf("prefix %q against pattern */run: "+
				"expected true (permissive — wildcard head), got %v", prefix, got)
		}
	}
}

// TestPatternConcreteSuffix_AndPrefix pins the helper-level contract
// for the narrower-fallback splitters. Standalone test on the helpers
// so failures localise to the splitter logic rather than the matcher.
func TestPatternConcreteSuffix_AndPrefix(t *testing.T) {
	cases := []struct {
		name, in, wantSuffix, wantPrefix string
	}{
		{"no_wildcards", "/var/log/foo.log", "/var/log/foo.log", "/var/log/foo.log"},
		{"trailing_star", "/var/log/pods/*", "", "/var/log/pods/"},
		{"leading_star", "*/run", "/run", ""},
		{"mid_ellipsis", "/var/⋯/log", "/log", "/var/"},
		{"both_mid", "/var/⋯/log/⋯/foo.log", "/foo.log", "/var/"},
		{"lone_star", "*", "", ""},
		{"lone_ellipsis", "⋯", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := patternConcreteSuffix(tc.in); got != tc.wantSuffix {
				t.Errorf("patternConcreteSuffix(%q) = %q, want %q", tc.in, got, tc.wantSuffix)
			}
			if got := patternConcretePrefix(tc.in); got != tc.wantPrefix {
				t.Errorf("patternConcretePrefix(%q) = %q, want %q", tc.in, got, tc.wantPrefix)
			}
		})
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
