package parse

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestParseLibrary(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		Parse(config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{
			name:     "args with first element",
			expr:     "parse.get_exec_path(['/bin/ls', '-la'], 'ls')",
			expected: "/bin/ls",
		},
		{
			name:     "args with empty first element",
			expr:     "parse.get_exec_path(['', '-la'], 'ls')",
			expected: "ls",
		},
		{
			name:     "empty args list",
			expr:     "parse.get_exec_path([], 'ls')",
			expected: "ls",
		},
		{
			name:     "single element in args",
			expr:     "parse.get_exec_path(['/usr/bin/python'], 'python')",
			expected: "/usr/bin/python",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, issues := env.Compile(tt.expr)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}

			result, _, err := program.Eval(map[string]interface{}{
				"event": map[string]interface{}{
					"args": []string{},
					"comm": "test",
				},
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}

			actual, ok := result.Value().(string)
			if !ok {
				t.Fatalf("expected string result, got %T", result.Value())
			}

			assert.Equal(t, tt.expected, actual, "result should match expected value")
		})
	}
}

func TestParseLibraryErrorCases(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		Parse(config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	tests := []struct {
		name        string
		expr        string
		expectError bool
	}{
		{
			name:        "wrong number of arguments",
			expr:        "parse.get_exec_path(['/bin/ls'])",
			expectError: true,
		},
		{
			name:        "wrong argument types",
			expr:        "parse.get_exec_path('not a list', 'ls')",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, issues := env.Compile(tt.expr)
			if issues != nil {
				if tt.expectError {
					return // Expected compilation error
				}
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				if tt.expectError {
					return // Expected program creation error
				}
				t.Fatalf("failed to create program: %v", err)
			}

			_, _, err = program.Eval(map[string]interface{}{
				"event": map[string]interface{}{
					"args": []string{},
					"comm": "test",
				},
			})
			if err != nil && tt.expectError {
				return // Expected evaluation error
			}
			if err != nil && !tt.expectError {
				t.Fatalf("unexpected error during evaluation: %v", err)
			}
		})
	}
}

// TestGetExecPath_SymmetryWithRecordingSide pins the contract that the
// rule-side resolver MUST agree with pkg/containerprofilemanager/v1/
// event_reporting.go:resolveExecPath. That recording function uses
//   1. exepath (kernel-authoritative)
//   2. argv[0] when non-empty
//   3. comm
// in that precedence order — so the path stored in the ApplicationProfile
// is whatever the kernel reports.
//
// If the rule side ignores exepath, the profile entry written under
// "/bin/sh" becomes unreachable when the runtime queries with the rule's
// resolved path "sh" (argv[0]), and R0001 fires spuriously on benign
// shell invocations — exactly the regression bobctl tune was hitting on
// merge/upstream-profile-rearch.
//
// These cases mirror TestResolveExecPath in pkg/containerprofilemanager/v1/
// event_reporting_test.go. They use a 3-arg overload of parse.get_exec_path
// that accepts (args, comm, exepath).
func TestGetExecPath_SymmetryWithRecordingSide(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		Parse(config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}

	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{
			name:     "exepath present (canonical exec)",
			expr:     "parse.get_exec_path(['/usr/sbin/unix_chkpwd', 'root'], 'unix_chkpwd', '/usr/sbin/unix_chkpwd')",
			expected: "/usr/sbin/unix_chkpwd",
		},
		{
			name: "exepath disagrees with argv[0] — exepath wins (argv[0] spoofing)",
			// kernel says /usr/bin/curl, argv[0] says sshd. Profile recorded by
			// resolveExecPath has "/usr/bin/curl" — rule MUST query the same.
			expr:     "parse.get_exec_path(['sshd', '-i'], 'curl', '/usr/bin/curl')",
			expected: "/usr/bin/curl",
		},
		{
			name:     "exepath empty (fexecve / AT_EMPTY_PATH) — fall back to argv[0]",
			expr:     "parse.get_exec_path(['unix_chkpwd', 'root'], 'unix_chkpwd', '')",
			expected: "unix_chkpwd",
		},
		{
			name:     "exepath + argv[0] empty — fall back to comm",
			expr:     "parse.get_exec_path(['', 'root'], 'unix_chkpwd', '')",
			expected: "unix_chkpwd",
		},
		{
			name:     "fork-shell case — kernel /bin/sh, argv[0] sh, comm sh",
			expr:     "parse.get_exec_path(['sh', '-c', 'echo'], 'sh', '/bin/sh')",
			expected: "/bin/sh",
		},
		{
			// Busybox-style symlink case: the user runs `/bin/sh` which
			// is a symlink to `/bin/busybox`. The kernel-resolved exepath
			// is `/bin/busybox`. The rule side queries the same identity
			// the recording side stored — exepath — so user-authored
			// profiles on busybox images must list `/bin/busybox`. Trusting
			// the absolute argv[0] here would let `exec -a /bin/sh sleep`
			// pass an ap.was_executed check for `/bin/sh`.
			name:     "busybox symlink — exepath /bin/busybox wins over argv[0]=/bin/sh",
			expr:     "parse.get_exec_path(['/bin/sh', '-c', 'echo hi'], 'sh', '/bin/busybox')",
			expected: "/bin/busybox",
		},
		{
			name:     "busybox symlink — exepath /bin/busybox wins over argv[0]=/usr/bin/nslookup",
			expr:     "parse.get_exec_path(['/usr/bin/nslookup', 'example.com'], 'nslookup', '/bin/busybox')",
			expected: "/bin/busybox",
		},
		{
			// Bare-argv[0] spoof — exepath still wins.
			name:     "bare argv[0] spoof — exepath wins",
			expr:     "parse.get_exec_path(['sshd', '-i'], 'curl', '/usr/bin/curl')",
			expected: "/usr/bin/curl",
		},
		{
			// Absolute argv[0] spoof — `exec -a /bin/sh sleep 2`.
			// Process lies about its identity via an allowed absolute
			// argv[0]; the real exe is /usr/bin/sleep. Rule-side resolver
			// MUST anchor on kernel-authoritative exepath, mirroring
			// resolveExecPath so ap.was_executed lookups reflect the
			// real binary. Regression pin for matthyx blocker on PR #805
			// (2026-05-27).
			name:     "absolute argv[0] spoof — exec -a /bin/sh sleep",
			expr:     "parse.get_exec_path(['/bin/sh', '2'], 'sleep', '/usr/bin/sleep')",
			expected: "/usr/bin/sleep",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, issues := env.Compile(tt.expr)
			if issues != nil {
				t.Fatalf("failed to compile expression: %v", issues.Err())
			}
			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("failed to create program: %v", err)
			}
			result, _, err := program.Eval(map[string]interface{}{
				"event": map[string]interface{}{
					"args":    []string{},
					"comm":    "test",
					"exepath": "",
				},
			})
			if err != nil {
				t.Fatalf("failed to eval program: %v", err)
			}
			actual, ok := result.Value().(string)
			if !ok {
				t.Fatalf("expected string result, got %T", result.Value())
			}
			assert.Equal(t, tt.expected, actual, "result should match expected value")
		})
	}
}
