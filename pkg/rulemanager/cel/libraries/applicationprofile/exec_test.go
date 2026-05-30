package applicationprofile

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
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
			// Profile entry has Args=["-la", "/tmp"]; runtime args differ at
			// position 1 (/home vs /tmp). CompareExecArgs walks the literal
			// segments, so the mismatch surfaces and the match fails. This
			// is the contract R0040 ("Unexpected process arguments") relies
			// on: path-allowed exec with mismatching argv must NOT match.
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
			// Profile entry has Args=["-la", "/tmp"] (non-empty); runtime
			// args is empty. matchExecArgsStrict treats this as anchored:
			// the profile demands at least the literal "-la" but there's
			// no runtime arg to consume. No match. (If the profile entry
			// also wanted to allow the no-args case, it would carry a
			// second ExecCalls entry for the same Path with empty Args.)
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

// TestExecWithArgsBusyboxMultiVector pins the Test_32 component-test contract
// at the unit level. In busybox-symlink containers the kernel-resolved
// /proc/<pid>/exe (and therefore event.exepath) is /bin/busybox for every
// applet exec, so parse.get_exec_path routes was_executed_with_args queries
// to /bin/busybox regardless of which symlink was invoked. The profile
// therefore carries multiple ExecCalls entries with the SAME Path
// (/bin/busybox) and DIFFERENT Args vectors — one per allowed argv shape.
// The matcher must walk every vector and accept if ANY matches.
//
// Failure modes this guards against:
//   - The wasExecutedWithArgs stub that returned true for any path-in-profile
//     match regardless of args (the bug that suppressed R0040 entirely on
//     #805's first 3 CT runs).
//   - extractExecsByPath overwriting prior entries when Paths collide (the
//     "last-write-wins" concern CodeRabbit/matthyx raised on PR #807).
//
// Test_32 has 4 subtests; this pins the contract for each:
//   sh_dash_c_matches_wildcard_trailing — argv matches profile [sh, -c, *].
//   sh_dash_x_mismatches_R0040          — argv mismatches at literal anchor.
//   echo_hello_matches_wildcard_trailing — argv matches profile [echo, hello, *].
//   echo_goodbye_mismatches_R0040       — argv mismatches at literal "hello".
func TestExecWithArgsBusyboxMultiVector(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "test-container"}},
		},
	})

	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Execs: []v1beta1.ExecCalls{
			// Three ExecCalls share Path=/bin/busybox with distinct argv
			// shapes. The projection layer appends them all into
			// ExecsByPath["/bin/busybox"]; the matcher walks every
			// vector and accepts if ANY matches.
			{Path: "/bin/busybox", Args: []string{"/bin/sleep", dynamicpathdetector.WildcardIdentifier}},
			{Path: "/bin/busybox", Args: []string{"/bin/sh", "-c", dynamicpathdetector.WildcardIdentifier}},
			{Path: "/bin/busybox", Args: []string{"/bin/echo", "hello", dynamicpathdetector.WildcardIdentifier}},
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
		args           []string
		expectedResult bool // true = silent (matches), false = R0040 must fire
	}{
		{
			name:           "sh_dash_c matches [sh,-c,*]",
			args:           []string{"/bin/sh", "-c", "echo hi"},
			expectedResult: true,
		},
		{
			name:           "sh_dash_x_dash_c mismatches at position 1 (-c vs -x)",
			args:           []string{"/bin/sh", "-x", "-c", "echo hi"},
			expectedResult: false,
		},
		{
			name:           "echo_hello matches [echo,hello,*]",
			args:           []string{"/bin/echo", "hello", "world", "from", "test"},
			expectedResult: true,
		},
		{
			name:           "echo_goodbye mismatches at position 1 (hello vs goodbye)",
			args:           []string{"/bin/echo", "goodbye", "world"},
			expectedResult: false,
		},
		{
			name:           "sleep matches [sleep,*] wildcard",
			args:           []string{"/bin/sleep", "infinity"},
			expectedResult: true,
		},
		{
			name:           "unknown applet mismatches all three vectors",
			args:           []string{"/bin/cat", "/etc/passwd"},
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_executed_with_args(containerID, path, args)`)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}
			prog, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}
			result, _, err := prog.Eval(map[string]any{
				"containerID": "test-container-id",
				"path":        "/bin/busybox",
				"args":        tc.args,
			})
			if err != nil {
				t.Fatalf("failed to evaluate expression: %v", err)
			}
			assert.Equal(t, tc.expectedResult, result.Value().(bool),
				"ap.was_executed_with_args(/bin/busybox, %v) — must return %v so R0040's `!was_executed_with_args` produces the right alert decision",
				tc.args, tc.expectedResult)
		})
	}
}

// TestExecWithArgsEmptyVectorDoesNotPoisonMatch reproduces the production
// failure that survived the first ExecsByPath wiring: R0040 stayed silent on
// every argv mismatch in #805 CT runs through the "side-effects" tip.
//
// In a real merged profile the SAME path can carry both a constrained vector
// (from the user-defined ApplicationProfile, e.g. [echo, hello, *]) AND a
// bare vector with no args (from the recorder, or a synthesised base CP, e.g.
// /bin/busybox observed with empty Args). extractExecsByPath stores the bare
// entry as an empty []string{}.
//
// dynamicpathdetector.CompareExecArgs treats an EMPTY profile vector as "no
// argv constraint" and returns true for ANY runtime args. When
// wasExecutedWithArgs ORs across every vector for the path, that one empty
// vector short-circuits the whole match to true — so !was_executed_with_args
// is always false and R0040 never fires, even for argv vectors that match
// none of the constrained entries. The fix (argvVectorMatches) treats an
// empty recorded vector as "ran with no args" (matches only empty runtime).
func TestExecWithArgsEmptyVectorDoesNotPoisonMatch(t *testing.T) {
	objCache := objectcachev1.RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}
	objCache.SetSharedContainerData("test-container-id", &objectcache.WatchedContainerData{
		ContainerType: objectcache.Container,
		ContainerInfos: map[objectcache.ContainerType][]objectcache.ContainerInfo{
			objectcache.Container: {{Name: "test-container"}},
		},
	})

	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Execs: []v1beta1.ExecCalls{
			// Bare recorder/synthetic entry: same path, NO args. This is the
			// poison vector — present in real merged profiles, absent from
			// the clean multi-vector test above.
			{Path: "/bin/busybox", Args: nil},
			// User-defined constrained vectors.
			{Path: "/bin/busybox", Args: []string{"/bin/echo", "hello", dynamicpathdetector.WildcardIdentifier}},
			{Path: "/bin/busybox", Args: []string{"/bin/sh", "-c", dynamicpathdetector.WildcardIdentifier}},
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
		args           []string
		expectedResult bool
	}{
		{
			name:           "echo goodbye still mismatches despite bare poison vector",
			args:           []string{"/bin/echo", "goodbye", "world"},
			expectedResult: false,
		},
		{
			name:           "sh -x -c still mismatches despite bare poison vector",
			args:           []string{"/bin/sh", "-x", "-c", "echo hi"},
			expectedResult: false,
		},
		{
			name:           "echo hello still matches its constrained vector",
			args:           []string{"/bin/echo", "hello", "world"},
			expectedResult: true,
		},
		{
			name:           "no-args invocation matches the bare vector",
			args:           []string{},
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_executed_with_args(containerID, path, args)`)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}
			prog, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}
			result, _, err := prog.Eval(map[string]any{
				"containerID": "test-container-id",
				"path":        "/bin/busybox",
				"args":        tc.args,
			})
			if err != nil {
				t.Fatalf("failed to evaluate expression: %v", err)
			}
			assert.Equal(t, tc.expectedResult, result.Value().(bool),
				"ap.was_executed_with_args(/bin/busybox, %v) — empty recorded vector must not poison the multi-vector OR",
				tc.args)
		})
	}
}
