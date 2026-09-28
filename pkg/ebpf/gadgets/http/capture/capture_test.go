package http_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Compile the production probe bodies with kernel helper substitutes. Only
// includes are removed; classification, syscall accounting and emission are real.
func harness(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("native HTTP probe regression requires a C compiler")
	}
	var source strings.Builder
	for _, path := range []string{"testdata/harness.h", "../program.h", "../program.bpf.c", "testdata/harness.c"} {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		for line := range strings.SplitSeq(string(data), "\n") {
			if (path == "../program.h" || path == "../program.bpf.c") && (strings.HasPrefix(line, "#include") || strings.HasPrefix(line, "#pragma once")) {
				continue
			}
			source.WriteString(line)
			source.WriteByte('\n')
		}
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "probe.c")
	bin := filepath.Join(dir, "probe")
	require.NoError(t, os.WriteFile(file, []byte(source.String()), 0600))
	out, err := exec.CommandContext(t.Context(), cc, "-O2", "-o", bin, file).CombinedOutput()
	require.NoError(t, err, "%s", out)
	return bin
}

func TestSyscallPayloadChunks(t *testing.T) {
	bin := harness(t)
	for _, mode := range []string{"w", "r", "wv", "rv"} {
		for _, size := range []int{10240, 16384, 16385, 20992, 40960} {
			for _, split := range []int{0, 8192} {
				t.Run(fmt.Sprintf("%s/%d/split%d", mode, size, split), func(t *testing.T) {
					payload := []byte("POST / HTTP/1.1\r\nContent-Length: 500000\r\n\r\n" + strings.Repeat("b", size))[:size]
					cmd := exec.CommandContext(t.Context(), bin, mode, "-1", fmt.Sprint(split), "0", "0")
					cmd.Stdin = bytes.NewReader(payload)
					var stderr bytes.Buffer
					cmd.Stderr = &stderr
					out, err := cmd.Output()
					require.NoError(t, err, "%s", stderr.String())
					require.Equal(t, payload, out)
					require.True(t, strings.HasSuffix(stderr.String(), " 0 0 0\n"), stderr.String())
				})
			}
		}
	}
}

func TestSyscallPartialAndLostChunks(t *testing.T) {
	bin := harness(t)
	for _, tc := range []struct {
		name, mode                                                 string
		size, ret, split, reserve, read, want, limit, alloc, fault int
	}{
		{name: "partial scalar", mode: "w", size: 40960, ret: 20992, want: 20992},
		{name: "partial vector", mode: "rv", size: 40960, ret: 20992, split: 10000, want: 20992},
		{name: "reserve second", mode: "w", size: 40960, ret: -1, reserve: 2, want: 16384, alloc: 1},
		{name: "read second", mode: "wv", size: 40960, ret: -1, read: 2, want: 16384, fault: 1},
		{name: "scalar work limit", mode: "w", size: 262145, ret: -1, want: 262144, limit: 1},
		{name: "scalar exact work limit", mode: "w", size: 262144, ret: -1, want: 262144},
		{name: "vector exact work limit", mode: "rv", size: 262144, ret: -1, split: 20000, want: 262144},
		{name: "vector byte work limit", mode: "wv", size: 262145, ret: -1, split: 20000, want: 262144, limit: 1},
		{name: "all 28 small vectors", mode: "wv", size: 28000, ret: -1, split: 1000, want: 28000},
		{name: "vector descriptor limit", mode: "wv", size: 30000, ret: -1, split: 1000, want: 28000, limit: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("POST / HTTP/1.1\r\nContent-Length: 500000\r\n\r\n" + strings.Repeat("b", tc.size))[:tc.size]
			cmd := exec.CommandContext(t.Context(), bin, tc.mode, fmt.Sprint(tc.ret), fmt.Sprint(tc.split), fmt.Sprint(tc.reserve), fmt.Sprint(tc.read))
			cmd.Stdin = bytes.NewReader(payload)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			require.NoError(t, err, "%s", stderr.String())
			require.Equal(t, payload[:tc.want], out)
			require.True(t, strings.HasSuffix(stderr.String(), fmt.Sprintf(" %d %d %d\n", tc.limit, tc.alloc, tc.fault)), stderr.String())
		})
	}
}
