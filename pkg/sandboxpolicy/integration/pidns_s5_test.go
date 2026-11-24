package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestS5PIDNamespaceInode: HostPIDNamespace compares the PID namespace
// inode, not only the PID numbers (S4 review v3, LOW 3/4): procRoot's
// self/ns/pid must name node-agent's own PID namespace.
func TestS5PIDNamespaceInode(t *testing.T) {
	if err := samePIDNamespace("/proc", "/proc"); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.MkdirAll(filepath.Join(other, "self/ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("pid:[1]", filepath.Join(other, "self/ns/pid")); err != nil {
		t.Fatal(err)
	}
	if err := samePIDNamespace("/proc", other); err == nil || !strings.Contains(err.Error(), "not node-agent's PID namespace") {
		t.Fatalf("another PID namespace inode: %v", err)
	}
	if err := samePIDNamespace("/proc", t.TempDir()); err == nil {
		t.Fatal("a missing ns/pid link passed")
	}
}
