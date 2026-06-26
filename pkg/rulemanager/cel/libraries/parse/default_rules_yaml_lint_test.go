package parse

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func defaultRulesYAMLPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", ".."))
	return filepath.Join(repoRoot, "tests", "chart", "templates", "node-agent", "default-rules.yaml")
}

// guardedExecPath matches the exepath-first ternary that wraps the 2-arg
// resolver — the backward-compatible form the bundled rules use:
//
//	event.exepath != "" ? event.exepath : parse.get_exec_path(event.args, event.comm)
//
// Both YAML renderings are tolerated: literal "" (block scalars) and the
// escaped \"\" (double-quoted scalars).
var guardedExecPath = regexp.MustCompile(`event\.exepath\s*!=\s*\\?"\\?"\s*\?\s*event\.exepath\s*:\s*parse\.get_exec_path\(\s*event\.args\s*,\s*event\.comm\s*\)`)

// twoArgExecPath matches a 2-arg parse.get_exec_path(event.args, event.comm).
// It does NOT match the 3-arg form, because there event.comm is followed by
// ", event.exepath" rather than ")".
var twoArgExecPath = regexp.MustCompile(`parse\.get_exec_path\(\s*event\.args\s*,\s*event\.comm\s*\)`)

// TestDefaultRulesYAML_NoUnguardedTwoArgGetExecPath pins exec-path resolution
// in the bundled rules to an exepath-first form. A *bare* 2-arg
// parse.get_exec_path(args, comm) re-introduces the fork-shell mismatch: the
// rule side evaluates to a bare comm (e.g. "sh") while the recording side
// stores the kernel-resolved exepath (e.g. "/bin/sh"), silently breaking
// ap.was_executed lookups for execve patterns like `sh -c …`.
//
// Two forms are allowed and must be used instead:
//   - the 3-arg parse.get_exec_path(event.args, event.comm, event.exepath)
//     overload (node-agent v0.3.147+), used by R0040; and
//   - the backward-compatible inline ternary
//     event.exepath != "" ? event.exepath : parse.get_exec_path(event.args, event.comm),
//     used by R0001/R0007/R1001/R1004 so they also run on agents predating the
//     3-arg overload.
//
// The check blanks out the guarded ternary occurrences (length-preserving so
// reported line numbers stay accurate), then flags any 2-arg call that remains.
func TestDefaultRulesYAML_NoUnguardedTwoArgGetExecPath(t *testing.T) {
	data, err := os.ReadFile(defaultRulesYAMLPath(t))
	if err != nil {
		t.Fatalf("read default-rules.yaml: %v", err)
	}

	cleaned := guardedExecPath.ReplaceAllFunc(data, func(m []byte) []byte {
		return bytes.Repeat([]byte(" "), len(m))
	})

	if locs := twoArgExecPath.FindAllIndex(cleaned, -1); len(locs) > 0 {
		lines := lineNumbers(data, locs)
		t.Errorf("found %d unguarded 2-arg parse.get_exec_path() call(s) at line(s) %v; "+
			"use the 3-arg form parse.get_exec_path(event.args, event.comm, event.exepath) or the "+
			"exepath-first ternary event.exepath != \"\" ? event.exepath : parse.get_exec_path(event.args, event.comm)",
			len(locs), lines)
	}
}

// TestDefaultRulesYAML_NoStringOnArgsList guards against CEL expressions that
// wrap the list-typed event.args field in string(). CEL's string() has no
// list overload, so e.g. string(event.args) compiles-then-fails at rule-eval
// time. When that expression is a rule's message or uniqueId, the rule manager
// drops the whole alert (rule_manager.go: getUniqueIdAndMessage error → the
// event is skipped) and spams error logs on every matching event — which broke
// R0040 delivery and tripped Test_02/Test_32. Render list fields with
// event.args.map(a, string(a)).join(" ") instead (precedent: R0006 uses
// event.flags.join(",")).
func TestDefaultRulesYAML_NoStringOnArgsList(t *testing.T) {
	data, err := os.ReadFile(defaultRulesYAMLPath(t))
	if err != nil {
		t.Fatalf("read default-rules.yaml: %v", err)
	}

	stringOnArgs := regexp.MustCompile(`string\(\s*event\.args\s*\)`)
	if locs := stringOnArgs.FindAllIndex(data, -1); len(locs) > 0 {
		lines := lineNumbers(data, locs)
		t.Errorf("found %d string(event.args) call(s) at line(s) %v; CEL string() has no list overload — "+
			"render with event.args.map(a, string(a)).join(\" \")", len(locs), lines)
	}
}

// TestDefaultRulesYAML_R1000DetectsDevShmViaArgv guards R1000 ("Process
// Executed from /dev/shm") against silently losing its /dev/shm detection.
// R1000 must inspect argv[0] (event.args[0]) and event.exepath / event.cwd
// directly — NOT route through parse.get_exec_path, because the 3-arg resolver
// prefers the kernel-resolved exepath (e.g. /bin/busybox for a busybox-symlinked
// applet) over the as-invoked argv[0] (/dev/shm/ls). Routing /dev/shm detection
// through get_exec_path therefore resolves the path away from /dev/shm and the
// rule never fires (regressed Test_02).
func TestDefaultRulesYAML_R1000DetectsDevShmViaArgv(t *testing.T) {
	data, err := os.ReadFile(defaultRulesYAMLPath(t))
	if err != nil {
		t.Fatalf("read default-rules.yaml: %v", err)
	}

	// Isolate the R1000 rule block: from its id line to the next rule's id line.
	text := string(data)
	start := strings.Index(text, `id: "R1000"`)
	if start < 0 {
		t.Fatal(`R1000 rule not found in default-rules.yaml`)
	}
	rest := text[start+len(`id: "R1000"`):]
	end := strings.Index(rest, `id: "R`)
	if end < 0 {
		end = len(rest)
	}
	block := rest[:end]

	if strings.Contains(block, "get_exec_path") {
		t.Errorf("R1000 routes /dev/shm detection through parse.get_exec_path; the resolver " +
			"prefers exepath over argv[0], so /dev/shm/<applet> resolves away from /dev/shm and " +
			"the rule never fires. Inspect event.args[0] / event.exepath / event.cwd directly.")
	}
	if !strings.Contains(block, "event.args[0]") {
		t.Errorf("R1000 must inspect argv[0] (event.args[0]) so an exec invoked as /dev/shm/<applet> " +
			"is detected even when exepath resolves to the symlink target (e.g. /bin/busybox)")
	}
}

func lineNumbers(data []byte, locs [][]int) []int {
	out := make([]int, 0, len(locs))
	for _, loc := range locs {
		line := 1
		for i := 0; i < loc[0] && i < len(data); i++ {
			if data[i] == '\n' {
				line++
			}
		}
		out = append(out, line)
	}
	return out
}
