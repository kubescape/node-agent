package utils

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveOpenPathProc pins the procfs resolution ladder against the live
// process: fd names the object exactly; a dead fd falls back to cwd-join for
// relative paths; the empty path resolves to nothing (kernel: openat("")
// names no object).
func TestResolveOpenPathProc(t *testing.T) {
	self := uint32(os.Getpid())

	f, err := os.CreateTemp(t.TempDir(), "resolve")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	want, _ := filepath.EvalSymlinks(f.Name())

	got := ResolveOpenPathProc(self, uint32(f.Fd()), "ignored-when-fd-resolves")
	if resolved, _ := filepath.EvalSymlinks(got); resolved != want {
		t.Fatalf("fd resolution = %q, want %q", got, want)
	}

	cwd, _ := os.Getwd()
	got = ResolveOpenPathProc(self, 0, "some/rel/name")
	if want := filepath.Join(cwd, "some/rel/name"); got != want {
		t.Fatalf("cwd-join = %q, want %q", got, want)
	}

	if got = ResolveOpenPathProc(self, 0, ""); got != "" {
		t.Fatalf("empty path must not resolve, got %q", got)
	}
	if got = ResolveOpenPathProc(0, 0, "x"); got != "" {
		t.Fatalf("pid 0 must not resolve, got %q", got)
	}
}
