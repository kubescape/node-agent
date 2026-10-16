package utils

import (
	"os"
	"path/filepath"
	"strings"
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
	defer func() { _ = f.Close() }()
	want, _ := filepath.EvalSymlinks(f.Name())

	got := ResolveOpenPathProc(self, uint32(f.Fd()), true, "ignored-when-fd-resolves")
	if resolved, _ := filepath.EvalSymlinks(got); resolved != want {
		t.Fatalf("fd resolution = %q, want %q", got, want)
	}

	// When fdValid is true and fd is 0, descriptor 0 is resolved from procfs
	// only if the target is an absolute filesystem path (rejecting pipes/sockets).
	if fd0Target, err := os.Readlink("/proc/self/fd/0"); err == nil && strings.HasPrefix(fd0Target, "/") {
		got = ResolveOpenPathProc(self, 0, true, "ignored-when-fd0-resolves")
		if got != fd0Target {
			t.Fatalf("fd 0 resolution = %q, want %q", got, fd0Target)
		}
	}

	// When fdValid is false, fd 0 is not inspected and relative path falls back to cwd-join.
	cwd, _ := os.Getwd()
	got = ResolveOpenPathProc(self, 0, false, "some/rel/name")
	if want := filepath.Join(cwd, "some/rel/name"); got != want {
		t.Fatalf("cwd-join = %q, want %q", got, want)
	}

	// When dirfd is explicitly AT_FDCWD, it joins with cwd.
	got = ResolveOpenPathProc(self, 0, false, "some/rel/name", AT_FDCWD)
	if want := filepath.Join(cwd, "some/rel/name"); got != want {
		t.Fatalf("AT_FDCWD join = %q, want %q", got, want)
	}

	// When dirfd is a valid directory descriptor, relative path resolves against dirfd.
	dir := t.TempDir()
	dirFile, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dirFile.Close() }()
	wantDir, _ := filepath.EvalSymlinks(dir)
	got = ResolveOpenPathProc(self, 0, false, "sub/file", int32(dirFile.Fd()))
	if want := filepath.Join(wantDir, "sub/file"); got != want {
		t.Fatalf("dirfd join = %q, want %q", got, want)
	}

	// When dirfd is invalid (not AT_FDCWD and not a valid fd), it must not resolve to cwd.
	if got = ResolveOpenPathProc(self, 0, false, "sub/file", -1); got != "" {
		t.Fatalf("invalid dirfd -1 must not resolve, got %q", got)
	}
	if got = ResolveOpenPathProc(self, 0, false, "sub/file", 99999); got != "" {
		t.Fatalf("invalid dirfd 99999 must not resolve, got %q", got)
	}

	// When dirfd points to a regular file (not a directory), relative openat fails with ENOTDIR;
	// resolution must return "" rather than fabricating a <file>/<raw> path.
	if got = ResolveOpenPathProc(self, 0, false, "sub/file", int32(f.Fd())); got != "" {
		t.Fatalf("regular-file dirfd must not resolve, got %q", got)
	}

	if got = ResolveOpenPathProc(self, 0, false, ""); got != "" {
		t.Fatalf("empty path must not resolve, got %q", got)
	}
	if got = ResolveOpenPathProc(0, 0, false, "x"); got != "" {
		t.Fatalf("pid 0 must not resolve, got %q", got)
	}
}
