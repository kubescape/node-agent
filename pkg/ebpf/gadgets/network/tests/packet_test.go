//go:build linux

package network_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Execute the production packet reader with bounded packet reads and captured
// events. The native harness substitutes kernel helpers, not packet logic.
func TestNetworkPackets(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("native C compiler unavailable")
	}
	var source strings.Builder
	for _, path := range []string{"testdata/harness.h", "../program.h", "../program.bpf.c", "testdata/packets.c"} {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		text := string(data)
		if path == "../program.bpf.c" {
			text = strings.ReplaceAll(text, "unsigned long long load_byte(const void *skb,\n    unsigned long long off) asm(\"llvm.bpf.load.byte\");", "")
		}
		for line := range strings.SplitSeq(text, "\n") {
			if (path == "../program.h" || path == "../program.bpf.c") && (strings.HasPrefix(line, "#include") || strings.HasPrefix(line, "#pragma once")) {
				continue
			}
			source.WriteString(line)
			source.WriteByte('\n')
		}
	}
	dir := t.TempDir()
	file, bin := filepath.Join(dir, "packets.c"), filepath.Join(dir, "packets")
	require.NoError(t, os.WriteFile(file, []byte(source.String()), 0600))
	out, err := exec.CommandContext(t.Context(), cc, "-O2", "-Wall", "-Werror", file, "-o", bin).CombinedOutput()
	require.NoError(t, err, "%s", out)
	out, err = exec.CommandContext(t.Context(), bin).CombinedOutput()
	require.NoError(t, err, "%s", out)
}
