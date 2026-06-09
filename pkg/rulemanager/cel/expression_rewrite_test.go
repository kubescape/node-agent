package cel

import (
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/parse"
)

func TestRewriteDeprecatedHelpers(t *testing.T) {
	tests := []struct {
		name               string
		input              string
		wantOutput         string
		wantNoticeCount    int
		wantNoticeContains string
	}{
		{
			name:               "canonical 2-arg rewritten to 3-arg",
			input:              `!ap.was_executed(event.containerId, parse.get_exec_path(event.args, event.comm))`,
			wantOutput:         `!ap.was_executed(event.containerId, parse.get_exec_path(event.args, event.comm, event.exepath))`,
			wantNoticeCount:    1,
			wantNoticeContains: "auto-rewrote",
		},
		{
			name:            "3-arg form already — unchanged, no notice",
			input:           `!ap.was_executed(event.containerId, parse.get_exec_path(event.args, event.comm, event.exepath))`,
			wantOutput:      `!ap.was_executed(event.containerId, parse.get_exec_path(event.args, event.comm, event.exepath))`,
			wantNoticeCount: 0,
		},
		{
			name:            "whitespace inside the call tolerated",
			input:           `parse.get_exec_path( event.args , event.comm )`,
			wantOutput:      `parse.get_exec_path(event.args, event.comm, event.exepath)`,
			wantNoticeCount: 1,
		},
		{
			name:            "multiple canonical 2-arg calls in one expression — all rewritten, single notice",
			input:           `parse.get_exec_path(event.args, event.comm) + parse.get_exec_path(event.args, event.comm)`,
			wantOutput:      `parse.get_exec_path(event.args, event.comm, event.exepath) + parse.get_exec_path(event.args, event.comm, event.exepath)`,
			wantNoticeCount: 1,
		},
		{
			name:               "non-event 2-arg — cannot auto-upgrade, notice emitted",
			input:              `parse.get_exec_path(myArgs, myComm)`,
			wantOutput:         `parse.get_exec_path(myArgs, myComm)`,
			wantNoticeCount:    1,
			wantNoticeContains: "cannot be auto-upgraded",
		},
		{
			name:               "literal-args 2-arg — cannot auto-upgrade",
			input:              `parse.get_exec_path(['/bin/ls'], 'ls')`,
			wantOutput:         `parse.get_exec_path(['/bin/ls'], 'ls')`,
			wantNoticeCount:    1,
			wantNoticeContains: "cannot be auto-upgraded",
		},
		{
			name:            "mixed canonical + non-canonical — canonical rewritten, both flagged",
			input:           `parse.get_exec_path(event.args, event.comm) && parse.get_exec_path(otherArgs, otherComm)`,
			wantOutput:      `parse.get_exec_path(event.args, event.comm, event.exepath) && parse.get_exec_path(otherArgs, otherComm)`,
			wantNoticeCount: 2,
		},
		{
			name:            "no get_exec_path at all — unchanged",
			input:           `event.containerId == 'foo'`,
			wantOutput:      `event.containerId == 'foo'`,
			wantNoticeCount: 0,
		},
		{
			name:            "default-rules.yaml line 434 form (chained call, multiple sites)",
			input:           `!ap.was_executed(event.containerId, parse.get_exec_path(event.args, event.comm)) && k8s.get_container_mount_paths(ns, pod, c).exists(mount, event.exepath.startsWith(mount) || parse.get_exec_path(event.args, event.comm).startsWith(mount))`,
			wantOutput:      `!ap.was_executed(event.containerId, parse.get_exec_path(event.args, event.comm, event.exepath)) && k8s.get_container_mount_paths(ns, pod, c).exists(mount, event.exepath.startsWith(mount) || parse.get_exec_path(event.args, event.comm, event.exepath).startsWith(mount))`,
			wantNoticeCount: 1,
		},
		{
			name:            "method-call chain on get_exec_path result",
			input:           `parse.get_exec_path(event.args, event.comm).startsWith('/dev/shm/')`,
			wantOutput:      `parse.get_exec_path(event.args, event.comm, event.exepath).startsWith('/dev/shm/')`,
			wantNoticeCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, notices := rewriteDeprecatedHelpers(tt.input)
			if got != tt.wantOutput {
				t.Errorf("rewrite output mismatch\n  input:    %s\n  got:      %s\n  expected: %s", tt.input, got, tt.wantOutput)
			}
			if len(notices) != tt.wantNoticeCount {
				t.Errorf("notice count: got %d, want %d\n  notices: %v", len(notices), tt.wantNoticeCount, notices)
			}
			if tt.wantNoticeContains != "" {
				found := false
				for _, n := range notices {
					if strings.Contains(n, tt.wantNoticeContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected at least one notice containing %q; got: %v", tt.wantNoticeContains, notices)
				}
			}
		})
	}
}

// TestRewriteIntegration_2ArgExpressionResolvesViaExepath proves the
// end-to-end SF-A guarantee: a RuleBinding shipped with the older 2-arg
// `parse.get_exec_path(event.args, event.comm)` form, when run through
// rewriteDeprecatedHelpers and compiled+evaluated by CEL, yields
// kernel-authoritative `event.exepath` — i.e. the spoof case `exec -a
// /bin/sh sleep` resolves to /usr/bin/sleep instead of /bin/sh, exactly
// as the 3-arg form would.
//
// This is the contract operators rely on when they upgrade the
// node-agent binary without touching their RuleBindings.
func TestRewriteIntegration_2ArgExpressionResolvesViaExepath(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		parse.Parse(config.Config{}),
	)
	if err != nil {
		t.Fatalf("failed to build CEL env: %v", err)
	}

	cases := []struct {
		name     string
		oldExpr  string // 2-arg form as written in legacy RuleBindings
		event    map[string]any
		expected string
	}{
		{
			name:    "absolute argv[0] spoof — exec -a /bin/sh sleep",
			oldExpr: `parse.get_exec_path(event.args, event.comm)`,
			event: map[string]any{
				"args":    []string{"/bin/sh", "2"},
				"comm":    "sleep",
				"exepath": "/usr/bin/sleep",
			},
			expected: "/usr/bin/sleep",
		},
		{
			name:    "bare argv[0] spoof — argv0=sshd, real exe curl",
			oldExpr: `parse.get_exec_path(event.args, event.comm)`,
			event: map[string]any{
				"args":    []string{"sshd", "-i"},
				"comm":    "curl",
				"exepath": "/usr/bin/curl",
			},
			expected: "/usr/bin/curl",
		},
		{
			name:    "shell-typed `ls` (bare argv[0]) — fork-shell case",
			oldExpr: `parse.get_exec_path(event.args, event.comm)`,
			event: map[string]any{
				"args":    []string{"ls", "-la"},
				"comm":    "ls",
				"exepath": "/bin/ls",
			},
			expected: "/bin/ls",
		},
		{
			name:    "busybox — exepath /bin/busybox wins over argv[0]=/bin/sh",
			oldExpr: `parse.get_exec_path(event.args, event.comm)`,
			event: map[string]any{
				"args":    []string{"/bin/sh", "-c", "echo hi"},
				"comm":    "sh",
				"exepath": "/bin/busybox",
			},
			expected: "/bin/busybox",
		},
		{
			name:    "fexecve (libpam) — exepath empty, falls back to argv[0]",
			oldExpr: `parse.get_exec_path(event.args, event.comm)`,
			event: map[string]any{
				"args":    []string{"unix_chkpwd", "root"},
				"comm":    "unix_chkpwd",
				"exepath": "",
			},
			expected: "unix_chkpwd",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Auto-rewrite, as registerExpression does.
			rewritten, notices := rewriteDeprecatedHelpers(tc.oldExpr)
			if len(notices) == 0 {
				t.Fatalf("expected at least one rewrite notice for input %q", tc.oldExpr)
			}

			// 2. Compile + run the REWRITTEN expression through the real
			//    CEL pipeline (same env the rule manager uses).
			ast, issues := env.Compile(rewritten)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("rewritten expression failed to compile: %v\n  rewritten: %s", issues.Err(), rewritten)
			}
			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("program creation failed: %v", err)
			}
			result, _, err := program.Eval(map[string]any{"event": tc.event})
			if err != nil {
				t.Fatalf("eval failed: %v", err)
			}
			got, ok := result.Value().(string)
			if !ok {
				t.Fatalf("expected string result, got %T (%v)", result.Value(), result.Value())
			}
			if got != tc.expected {
				t.Errorf("integrated rewrite+eval mismatch\n  legacy expression: %s\n  rewritten:         %s\n  event:             %v\n  got:               %q\n  want:              %q",
					tc.oldExpr, rewritten, tc.event, got, tc.expected)
			}
		})
	}
}
