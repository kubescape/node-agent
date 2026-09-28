package httpcapture

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Compile the production classifier and syscall probes against deterministic
// stand-ins for kernel maps, user-memory reads, and the output ring. Socket
// metadata extraction is deliberately outside this framing/lifecycle test.
func TestHTTPResponseContinuations(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("native C compiler unavailable")
	}
	program, err := os.ReadFile("../program.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	header, err := os.ReadFile("../program.h")
	if err != nil {
		t.Fatal(err)
	}
	harness, err := os.ReadFile("testdata/continuations.c")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(program), "static __always_inline int get_http_type(")
	if start < 0 {
		t.Fatal("production HTTP classifier not found")
	}
	body := strings.ReplaceAll(string(header), "#include <gadget/types.h>", "")
	body = strings.ReplaceAll(body, "#pragma once", "")
	extractDeclaration := func(marker string) string {
		begin := strings.Index(string(program), marker)
		if begin < 0 {
			t.Fatalf("production declaration %q not found", marker)
		}
		end := strings.Index(string(program[begin:]), "};")
		if end < 0 {
			t.Fatalf("production declaration %q is incomplete", marker)
		}
		return string(program[begin : begin+end+2])
	}
	harnessSource := strings.Replace(string(harness), "/* PRODUCTION_METADATA */", extractDeclaration("struct http_metadata {"), 1)
	harnessSource = strings.Replace(harnessSource, "/* PRODUCTION_LOSS_ENUM */", extractDeclaration("enum http_capture_loss {"), 1)
	source := strings.Replace(harnessSource, "/* PRODUCTION_HEADER */", body, 1)
	source = strings.Replace(source, "/* PRODUCTION_PROBES */", string(program[start:]), 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "continuations.c")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "continuations")
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Werror", "-Wno-unknown-pragmas", path, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile production probes: %v\n%s", err, out)
	}
	for _, scenario := range []string{"read", "readv", "recvmsg", "budget", "peek_scalar", "peek_vector", "failed_msghdr", "slow_body", "expiry", "refresh", "store_failed", "large_read", "large_readv", "large_recvmsg", "split_readv", "split_recvmsg", "mixed_partial"} {
		t.Run(scenario, func(t *testing.T) {
			if out, err := exec.Command(binary, scenario).CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
		})
	}
}
