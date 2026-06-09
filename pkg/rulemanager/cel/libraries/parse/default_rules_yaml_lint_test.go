package parse

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestDefaultRulesYAML_NoTwoArgGetExecPath pins the migration of bundled
// rule expressions to the 3-arg parse.get_exec_path(args, comm, exepath).
// Any 2-arg call site re-introduces the fork-shell mismatch where the rule
// side evaluates to a bare comm (e.g. "sh") while the recording side stores
// the resolved exepath (e.g. "/bin/sh") — silently breaking ap.was_executed
// lookups for execve patterns like `sh -c …` whose argv[0] is just "sh".
func TestDefaultRulesYAML_NoTwoArgGetExecPath(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", ".."))
	yamlPath := filepath.Join(repoRoot, "tests", "chart", "templates", "node-agent", "default-rules.yaml")

	data, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("read %s: %v", yamlPath, err)
	}

	// Match parse.get_exec_path( args , comm ) — i.e. exactly two arguments,
	// no third event.exepath. Whitespace between args is tolerated.
	twoArg := regexp.MustCompile(`parse\.get_exec_path\(\s*event\.args\s*,\s*event\.comm\s*\)`)
	if locs := twoArg.FindAllIndex(data, -1); len(locs) > 0 {
		lines := lineNumbers(data, locs)
		t.Errorf("found %d 2-arg parse.get_exec_path() call(s) at line(s) %v; migrate to parse.get_exec_path(event.args, event.comm, event.exepath)", len(locs), lines)
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
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", ".."))
	yamlPath := filepath.Join(repoRoot, "tests", "chart", "templates", "node-agent", "default-rules.yaml")

	data, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("read %s: %v", yamlPath, err)
	}

	stringOnArgs := regexp.MustCompile(`string\(\s*event\.args\s*\)`)
	if locs := stringOnArgs.FindAllIndex(data, -1); len(locs) > 0 {
		lines := lineNumbers(data, locs)
		t.Errorf("found %d string(event.args) call(s) at line(s) %v; CEL string() has no list overload — "+
			"render with event.args.map(a, string(a)).join(\" \")", len(locs), lines)
	}
}

// TestDefaultRulesYAML_R1000DetectsDevShmViaArgv guards R1000 ("Process
// executed from malicious source") against silently losing its /dev/shm
// detection. R1000 must inspect argv[0] (event.args[0]) and event.exepath /
// event.cwd directly — NOT route through parse.get_exec_path, because the
// 3-arg resolver prefers the kernel-resolved exepath (e.g. /bin/busybox for a
// busybox-symlinked applet) over the as-invoked argv[0] (/dev/shm/ls). Routing
// /dev/shm detection through get_exec_path therefore resolves the path away
// from /dev/shm and the rule never fires (regressed Test_02).
func TestDefaultRulesYAML_R1000DetectsDevShmViaArgv(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", ".."))
	yamlPath := filepath.Join(repoRoot, "tests", "chart", "templates", "node-agent", "default-rules.yaml")

	data, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("read %s: %v", yamlPath, err)
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
