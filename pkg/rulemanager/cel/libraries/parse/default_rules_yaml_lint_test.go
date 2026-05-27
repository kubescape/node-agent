package parse

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
