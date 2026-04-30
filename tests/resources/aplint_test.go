// AP-fixture lint tests.
//
// Validates every ApplicationProfile / NetworkNeighborhood YAML under
// tests/resources/ against the ground-truth syntax rules learned from a
// real auto-recorded AP for curlimages/curl:8.5.0 (originally captured
// by the fork in commit fea3b062 — known-application-profile.yaml). Each
// rule maps a real-world drift mode that has bitten the fork once already
// (e.g. argv[0] basename vs full path — Test_32 first run on PR #37).
//
// Runs as a regular `go test ./...` — no component tag, no kind cluster.
//
// LintApplicationProfile is exported (uppercase) and returns []Violation
// rather than calling t.Errorf directly, so this whole file can be lifted
// into a standalone bobctl subcommand `bobctl lint <ap.yaml>` without any
// testing-package dependency. The Test_* functions below are just thin
// wrappers that turn violations into t.Errorf calls.
package resources

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// applicationProfileLike captures only the fields we lint; we don't import
// the storage v1beta1 types because we want this lint runnable in isolation.
type applicationProfileLike struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Containers []struct {
			Name  string `json:"name"`
			Execs []struct {
				Path string   `json:"path"`
				Args []string `json:"args"`
			} `json:"execs"`
			Opens []struct {
				Path  string   `json:"path"`
				Flags []string `json:"flags"`
			} `json:"opens"`
		} `json:"containers"`
	} `json:"spec"`
}

// Violation is a single rule failure — id, target file (if any), and a
// human-readable message. Returned by LintApplicationProfile so callers
// can treat lint output as data (CLI exit code, JSON, t.Errorf, etc).
type Violation struct {
	Rule string
	Path string
	Msg  string
}

func (v Violation) String() string {
	if v.Path != "" {
		return fmt.Sprintf("[%s] %s: %s", v.Rule, v.Path, v.Msg)
	}
	return fmt.Sprintf("[%s] %s", v.Rule, v.Msg)
}

// validOpenFlags is the set of O_* flags the fork has seen in real
// auto-recorded profiles. Extend as new flags appear; a typo'd flag
// (e.g. `O_LARGEFLE`) is caught immediately.
var validOpenFlags = map[string]bool{
	"O_RDONLY":    true,
	"O_WRONLY":    true,
	"O_RDWR":      true,
	"O_CLOEXEC":   true,
	"O_LARGEFILE": true,
	"O_DIRECTORY": true,
	"O_NONBLOCK":  true,
	"O_APPEND":    true,
	"O_CREAT":     true,
	"O_EXCL":      true,
	"O_TRUNC":     true,
	"O_NOFOLLOW":  true,
	"O_NOATIME":   true,
	"O_DIRECT":    true,
	"O_SYNC":      true,
	"O_PATH":      true,
	"O_TMPFILE":   true,
}

// dynamicIdentifier and wildcardIdentifier mirror the constants in
// storage/pkg/registry/file/dynamicpathdetector. Duplicated here so this
// linter has zero dependency on the storage module.
const (
	dynamicIdentifier  = "⋯"
	wildcardIdentifier = "*"
)

// LintApplicationProfileYAML parses a YAML doc as an ApplicationProfile and
// runs all rules. Returns the slice of violations (empty == clean). Pure
// function — no I/O, no testing-package coupling.
func LintApplicationProfileYAML(doc []byte, sourceLabel string) []Violation {
	var ap applicationProfileLike
	if err := yaml.Unmarshal(doc, &ap); err != nil {
		return []Violation{{Rule: "R-AP-00", Path: sourceLabel, Msg: fmt.Sprintf("yaml parse: %v", err)}}
	}
	return LintApplicationProfile(&ap, sourceLabel)
}

// LintApplicationProfile runs every rule against an already-parsed AP.
// Returns the slice of violations (empty == clean).
//
// Rule IDs:
//   R-AP-00 — yaml parse failure (only from LintApplicationProfileYAML)
//   R-AP-01 — kind must be ApplicationProfile
//   R-AP-02 — at least one container
//   R-AP-03 — container name non-empty
//   R-AP-10 — exec.path absolute
//   R-AP-11 — exec.path no wildcards
//   R-AP-12 — exec.args[0] equals exec.path (or wildcard)
//   R-AP-13 — exec.args wildcard tokens are whole-word
//   R-AP-20 — open.path non-empty + absolute
//   R-AP-21 — open.flags non-empty
//   R-AP-22 — open.flags from known O_* set
func LintApplicationProfile(ap *applicationProfileLike, src string) []Violation {
	var v []Violation
	add := func(rule, msg string) { v = append(v, Violation{Rule: rule, Path: src, Msg: msg}) }

	if ap.Kind != "ApplicationProfile" {
		add("R-AP-01", fmt.Sprintf("kind is %q, expected \"ApplicationProfile\"", ap.Kind))
	}
	if len(ap.Spec.Containers) == 0 {
		add("R-AP-02", "spec.containers is empty")
		return v
	}

	for ci, c := range ap.Spec.Containers {
		if c.Name == "" {
			add("R-AP-03", fmt.Sprintf("spec.containers[%d].name is empty", ci))
		}

		for ei, e := range c.Execs {
			if e.Path == "" {
				add("R-AP-10", fmt.Sprintf("containers[%d].execs[%d].path is empty", ci, ei))
				continue
			}
			if !strings.HasPrefix(e.Path, "/") {
				add("R-AP-10", fmt.Sprintf("containers[%d].execs[%d].path %q must be absolute (start with /)", ci, ei, e.Path))
			}
			if strings.Contains(e.Path, dynamicIdentifier) || strings.Contains(e.Path, wildcardIdentifier) {
				add("R-AP-11", fmt.Sprintf("containers[%d].execs[%d].path %q must NOT contain wildcards (only args[*] may)", ci, ei, e.Path))
			}

			if len(e.Args) == 0 {
				continue // path-only entry is legal
			}

			// R-AP-12: args[0] must equal the full exec.path. The eBPF
			// tracer captures argv[0] as the full binary path; profile
			// entries that use a basename (e.g. "sh" instead of "/bin/sh")
			// silently fail to match at runtime. Caught the hard way on
			// Test_32's first CI run (PR #37 run 25178930763). Exception:
			// args[0] may be the wildcard token if the user genuinely
			// means "any binary at this path".
			if e.Args[0] != e.Path && e.Args[0] != wildcardIdentifier {
				add("R-AP-12", fmt.Sprintf("containers[%d].execs[%d].args[0] = %q, must equal path %q (eBPF captures argv[0] as full path)", ci, ei, e.Args[0], e.Path))
			}

			for ai, a := range e.Args {
				if a == "" {
					add("R-AP-13", fmt.Sprintf("containers[%d].execs[%d].args[%d] is empty", ci, ei, ai))
				}
				if strings.Contains(a, dynamicIdentifier) && a != dynamicIdentifier {
					add("R-AP-13", fmt.Sprintf("containers[%d].execs[%d].args[%d] = %q — ⋯ must be its own token, not embedded", ci, ei, ai, a))
				}
			}
		}

		for oi, o := range c.Opens {
			if o.Path == "" {
				add("R-AP-20", fmt.Sprintf("containers[%d].opens[%d].path is empty", ci, oi))
				continue
			}
			if !strings.HasPrefix(o.Path, "/") {
				add("R-AP-20", fmt.Sprintf("containers[%d].opens[%d].path %q must be absolute", ci, oi, o.Path))
			}
			if len(o.Flags) == 0 {
				add("R-AP-21", fmt.Sprintf("containers[%d].opens[%d].flags is empty", ci, oi))
			}
			for fi, f := range o.Flags {
				if !validOpenFlags[f] {
					add("R-AP-22", fmt.Sprintf("containers[%d].opens[%d].flags[%d] = %q — not a recognised O_* flag (typo?)", ci, oi, fi, f))
				}
			}
		}
	}
	return v
}

// ---------------------------------------------------------------------------
// Test layer — walk YAMLs in this directory, run the linter, surface
// violations as t.Errorf.
// ---------------------------------------------------------------------------

func TestApplicationProfileFixturesLint(t *testing.T) {
	matches, err := filepath.Glob("*.yaml")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Skip("no YAML fixtures found — running outside tests/resources?")
	}

	for _, p := range matches {
		p := p
		t.Run(filepath.Base(p), func(t *testing.T) {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			if !strings.Contains(string(data), "kind: ApplicationProfile") {
				t.Skipf("not an ApplicationProfile fixture")
			}
			for _, v := range LintApplicationProfileYAML(data, p) {
				t.Errorf("%s", v)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Self-tests — feed deliberately-bad YAML, verify the expected rule fires.
// Pin rule semantics so a refactor can't silently drop a check.
// ---------------------------------------------------------------------------

func ruleFired(violations []Violation, ruleID string) bool {
	for _, v := range violations {
		if v.Rule == ruleID {
			return true
		}
	}
	return false
}

func TestLinter_R_AP_12_argv0_must_be_full_path(t *testing.T) {
	bad := []byte(`
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata: { name: bad }
spec:
  containers:
  - name: c
    execs:
    - path: /bin/sh
      args: ["sh", "-c", "echo hi"]
`)
	if !ruleFired(LintApplicationProfileYAML(bad, "<inline>"), "R-AP-12") {
		t.Fatal("expected R-AP-12 violation for basename argv[0]")
	}
}

func TestLinter_R_AP_11_path_no_wildcards(t *testing.T) {
	bad := []byte(`
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata: { name: bad }
spec:
  containers:
  - name: c
    execs:
    - path: /usr/bin/*
      args: ["/usr/bin/curl"]
`)
	if !ruleFired(LintApplicationProfileYAML(bad, "<inline>"), "R-AP-11") {
		t.Fatal("expected R-AP-11 violation for wildcard in path")
	}
}

func TestLinter_R_AP_22_unknown_open_flag(t *testing.T) {
	bad := []byte(`
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata: { name: bad }
spec:
  containers:
  - name: c
    opens:
    - path: /etc/passwd
      flags: ["O_RDONLY", "O_LARGEFLE"]
`)
	if !ruleFired(LintApplicationProfileYAML(bad, "<inline>"), "R-AP-22") {
		t.Fatal("expected R-AP-22 violation for typo'd flag")
	}
}

func TestLinter_R_AP_10_path_must_be_absolute(t *testing.T) {
	bad := []byte(`
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata: { name: bad }
spec:
  containers:
  - name: c
    execs:
    - path: bin/sh
      args: ["bin/sh"]
`)
	if !ruleFired(LintApplicationProfileYAML(bad, "<inline>"), "R-AP-10") {
		t.Fatal("expected R-AP-10 violation for relative path")
	}
}

func TestLinter_R_AP_12_wildcard_argv0_allowed(t *testing.T) {
	// args[0] = "*" is the rare-but-legal "match any binary at this path" case.
	ok := []byte(`
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata: { name: ok }
spec:
  containers:
  - name: c
    execs:
    - path: /bin/sh
      args: ["*"]
`)
	if ruleFired(LintApplicationProfileYAML(ok, "<inline>"), "R-AP-12") {
		t.Fatal("R-AP-12 must NOT fire when args[0] is the wildcard token")
	}
}

func TestLinter_canonical_AP_passes(t *testing.T) {
	// The fork's reference profile (from fea3b062) is the gold standard;
	// regressions here mean the linter has drifted from real-world syntax.
	data, err := os.ReadFile("known-application-profile.yaml")
	if err != nil {
		t.Skipf("canonical AP fixture not present: %v", err)
	}
	violations := LintApplicationProfileYAML(data, "known-application-profile.yaml")
	if len(violations) > 0 {
		for _, v := range violations {
			t.Errorf("%s", v)
		}
	}
}
