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

// TestArgvVectorMatches exhaustively pins the per-vector argv matching used by
// ap.was_executed_with_args (and therefore R0040). It exercises argvVectorMatches
// directly — the single-vector comparator — across every token shape the
// profile can carry:
//
//	literal            — exact string equality
//	"⋯" (Dynamic)      — exactly ONE arg, any value
//	"*" (Wildcard)     — ZERO or more args
//	embedded "⋯"       — a path with a dynamic segment INSIDE one arg
//	                     (the postgres / versioned-binary case)
//
// The "want" column is the contract: true => exec is known-with-these-args
// (R0040 silent); false => argv mismatch (R0040 fires).
func TestArgvVectorMatches(t *testing.T) {
	const wild = dynamicpathdetector.WildcardIdentifier // "*"
	const ell = dynamicpathdetector.DynamicIdentifier   // "⋯"

	cases := []struct {
		name    string
		profile []string
		runtime []string
		want    bool
	}{
		// ---- symlinked busybox applet: NO args ----
		{"no-args: empty profile matches empty runtime", []string{}, []string{}, true},
		{"no-args: empty profile rejects non-empty runtime", []string{}, []string{"/bin/echo", "x"}, false},

		// ---- symlinked busybox applet: literal args only ----
		{"literal: exact match", []string{"/bin/cp", "-r"}, []string{"/bin/cp", "-r"}, true},
		{"literal: value mismatch", []string{"/bin/cp", "-r"}, []string{"/bin/cp", "-f"}, false},
		{"literal: runtime too long (anchored)", []string{"/bin/cp", "-r"}, []string{"/bin/cp", "-r", "x"}, false},
		{"literal: runtime too short (anchored)", []string{"/bin/cp", "-r"}, []string{"/bin/cp"}, false},

		// ---- with WILDCARD "*" (zero or more) ----
		{"wildcard: trailing * absorbs many", []string{"/bin/echo", "hello", wild}, []string{"/bin/echo", "hello", "a", "b", "c"}, true},
		{"wildcard: trailing * absorbs zero", []string{"/bin/echo", "hello", wild}, []string{"/bin/echo", "hello"}, true},
		{"wildcard: literal anchor before * mismatches", []string{"/bin/echo", "hello", wild}, []string{"/bin/echo", "goodbye", "x"}, false},
		{"wildcard: leading * absorbs prefix", []string{wild, "--end"}, []string{"a", "b", "--end"}, true},

		// ---- with ELLIPSIS "⋯" (exactly one) ----
		{"ellipsis: matches exactly one arg", []string{"/bin/sh", "-c", ell}, []string{"/bin/sh", "-c", "echo hi"}, true},
		{"ellipsis: rejects zero (needs one)", []string{"/bin/sh", "-c", ell}, []string{"/bin/sh", "-c"}, false},
		{"ellipsis: rejects two (exactly one)", []string{"/bin/sh", "-c", ell}, []string{"/bin/sh", "-c", "a", "b"}, false},
		{"ellipsis: mid-vector with literal after", []string{"--user", ell, "--port", "8080"}, []string{"--user", "alice", "--port", "8080"}, true},
		{"ellipsis: mid-vector trailing literal mismatch", []string{"--user", ell, "--port", "8080"}, []string{"--user", "alice", "--port", "9090"}, false},

		// ---- WILDCARD + ELLIPSIS together ----
		{"ellipsis then wildcard: one then zero+", []string{"/bin/foo", ell, wild}, []string{"/bin/foo", "a"}, true},
		{"ellipsis then wildcard: one then many", []string{"/bin/foo", ell, wild}, []string{"/bin/foo", "a", "b", "c"}, true},
		{"ellipsis then wildcard: zero args fails (⋯ needs one)", []string{"/bin/foo", ell, wild}, []string{"/bin/foo"}, false},
		{"wildcard then ellipsis: prefix then one", []string{"/bin/foo", wild, ell}, []string{"/bin/foo", "a", "b", "last"}, true},

		// ---- ALL combined: literal + ⋯ + literal + * ----
		{"all: literal,⋯,literal,* matches", []string{"/bin/tool", "sub", ell, "--flag", wild}, []string{"/bin/tool", "sub", "X", "--flag", "a", "b"}, true},
		{"all: literal,⋯,literal,* trailing-only ok (* zero)", []string{"/bin/tool", "sub", ell, "--flag", wild}, []string{"/bin/tool", "sub", "X", "--flag"}, true},
		{"all: literal,⋯,literal,* literal-anchor mismatch", []string{"/bin/tool", "sub", ell, "--flag", wild}, []string{"/bin/tool", "sub", "X", "--nope", "a"}, false},

		// ---- NON-symlinked, versioned binary: postgres (⋯ embedded in argv[0]) ----
		// Profile argv[0] carries a dynamic PATH segment; runtime argv[0] has the
		// concrete version. The remaining args are exact flags.
		{
			"postgres: versioned argv[0] + exact flags",
			[]string{
				"/usr/lib/postgresql/" + ell + "/bin/postgres",
				"--check", "-F",
				"-c", "log_checkpoints=false",
				"-c", "max_connections=100",
				"-c", "shared_buffers=16384",
				"-c", "dynamic_shared_memory_type=posix",
			},
			[]string{
				"/usr/lib/postgresql/16/bin/postgres",
				"--check", "-F",
				"-c", "log_checkpoints=false",
				"-c", "max_connections=100",
				"-c", "shared_buffers=16384",
				"-c", "dynamic_shared_memory_type=posix",
			},
			true,
		},
		{
			"postgres: versioned argv[0] matches but a flag value differs",
			[]string{
				"/usr/lib/postgresql/" + ell + "/bin/postgres",
				"-c", "max_connections=100",
			},
			[]string{
				"/usr/lib/postgresql/16/bin/postgres",
				"-c", "max_connections=9999",
			},
			false,
		},
		{
			"postgres: versioned argv[0] with trailing * over the -c flags",
			[]string{
				"/usr/lib/postgresql/" + ell + "/bin/postgres",
				"--check", wild,
			},
			[]string{
				"/usr/lib/postgresql/16/bin/postgres",
				"--check", "-c", "log_checkpoints=false",
			},
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := argvVectorMatches(tc.profile, tc.runtime)
			assert.Equalf(t, tc.want, got, "argvVectorMatches(%v, %v) = %v, want %v",
				tc.profile, tc.runtime, got, tc.want)
		})
	}
}

// TestArgvVectorMatches_ParityWithStorage pins that the NA reimplementation
// has NOT diverged from storage's CompareExecArgs on the semantics they
// share — the "*" / bare-"⋯" / literal handling. For every NON-empty,
// NON-embedded-⋯ profile vector, the two MUST agree. (The two intentional
// differences — empty profile is strict here, and embedded-⋯ args are
// path-matched here — are covered by the matrix above and excluded from this
// parity set.)
func TestArgvVectorMatches_ParityWithStorage(t *testing.T) {
	const wild = dynamicpathdetector.WildcardIdentifier
	const ell = dynamicpathdetector.DynamicIdentifier

	profiles := [][]string{
		{"a"}, {"a", "b"}, {"a", wild}, {wild, "b"}, {"a", ell, "c"},
		{ell}, {ell, ell}, {"a", ell, wild}, {wild, ell}, {"a", wild, "c"},
		{"-c", "log=false"}, {"--user", ell, "--port", "8080"},
		{wild}, {"a", "b", wild, "d"},
	}
	runtimes := [][]string{
		{}, {"a"}, {"a", "b"}, {"a", "b", "c"}, {"x"},
		{"a", "x", "c"}, {"a", "b", "c", "d"}, {"--user", "alice", "--port", "8080"},
		{"-c", "log=false"}, {"a", "y"},
	}

	for _, p := range profiles {
		// Skip vectors with an embedded-⋯ arg (path-aware here, literal in
		// storage) — those are an intentional divergence, tested separately.
		skip := false
		for _, a := range p {
			if a != ell && a != wild && containsEllipsis(a) {
				skip = true
			}
		}
		if skip {
			continue
		}
		for _, r := range runtimes {
			want := dynamicpathdetector.CompareExecArgs(p, r) // storage's matcher
			got := argvVectorMatches(p, r)
			assert.Equalf(t, want, got,
				"parity mismatch: profile=%v runtime=%v — storage=%v na=%v", p, r, want, got)
		}
	}
}

func containsEllipsis(s string) bool {
	return len(s) != len(dynamicpathdetector.DynamicIdentifier) &&
		// contains but isn't the bare token
		stringsContains(s, dynamicpathdetector.DynamicIdentifier)
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestWasExecutedWithArgs_PostgresEndToEnd drives the FULL CEL helper
// ap.was_executed_with_args for the non-symlinked, versioned-binary case
// where "⋯" appears in BOTH the path and argv[0]. At runtime the path
// resolves to a concrete version, so:
//
//   - the path "/usr/lib/postgresql/⋯/bin/postgres" lands in Execs.Patterns
//     and is matched against the runtime "/usr/lib/postgresql/16/bin/postgres"
//     via CompareDynamic (the pattern branch of wasExecutedWithArgs), then
//   - the argv vector is matched via argvVectorMatches, whose argv[0] also
//     carries "⋯" and is path-matched.
//
// This exercises a different code path than the busybox exact-path cases
// (Patterns vs Values) and proves R0040's decision end-to-end:
//
//	match  => was_executed_with_args true  => R0040 silent (allowed).
//	no match => false => R0040 fires (unexpected args).
func TestWasExecutedWithArgs_PostgresEndToEnd(t *testing.T) {
	const ell = dynamicpathdetector.DynamicIdentifier
	pgPath := "/usr/lib/postgresql/" + ell + "/bin/postgres"
	pgArgv0 := pgPath

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
			{Path: pgPath, Args: []string{
				pgArgv0, "--check", "-F",
				"-c", "log_checkpoints=false",
				"-c", "max_connections=100",
				"-c", "shared_buffers=16384",
				"-c", "dynamic_shared_memory_type=posix",
			}},
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
		t.Fatalf("env: %v", err)
	}

	const runtimePath = "/usr/lib/postgresql/16/bin/postgres" // ⋯ resolved to "16"
	cases := []struct {
		name string
		args []string
		want bool // was_executed_with_args; false => R0040 fires
	}{
		{
			"exact recorded postgres start matches",
			[]string{runtimePath, "--check", "-F",
				"-c", "log_checkpoints=false",
				"-c", "max_connections=100",
				"-c", "shared_buffers=16384",
				"-c", "dynamic_shared_memory_type=posix"},
			true,
		},
		{
			"tampered flag value mismatches",
			[]string{runtimePath, "--check", "-F",
				"-c", "log_checkpoints=false",
				"-c", "max_connections=99999",
				"-c", "shared_buffers=16384",
				"-c", "dynamic_shared_memory_type=posix"},
			false,
		},
		{
			"different postgres version still matches the ⋯ path segment",
			[]string{"/usr/lib/postgresql/15/bin/postgres", "--check", "-F",
				"-c", "log_checkpoints=false",
				"-c", "max_connections=100",
				"-c", "shared_buffers=16384",
				"-c", "dynamic_shared_memory_type=posix"},
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(`ap.was_executed_with_args(containerID, path, args)`)
			if issues != nil {
				t.Fatalf("compile: %v", issues.Err())
			}
			prog, err := env.Program(ast)
			if err != nil {
				t.Fatalf("program: %v", err)
			}
			res, _, err := prog.Eval(map[string]any{
				"containerID": "test-container-id",
				"path":        runtimePathOf(tc.args),
				"args":        tc.args,
			})
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			assert.Equalf(t, tc.want, res.Value().(bool),
				"was_executed_with_args(path=%s, args=%v)", runtimePathOf(tc.args), tc.args)
		})
	}
}

// runtimePathOf returns argv[0] (the resolved exec path) for the eval input.
func runtimePathOf(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}
