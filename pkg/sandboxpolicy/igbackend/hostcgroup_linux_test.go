package igbackend

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ReadHostProcessCgroup reads only from procfs: a fake root is refused
// before anything is read from it.
func TestReadHostProcessCgroupRefusesNonProcfs(t *testing.T) {
	root := t.TempDir()
	pid := os.Getpid()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::/fake\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHostProcessCgroup(root, uint32(pid)); err == nil || !strings.Contains(err.Error(), "not procfs") {
		t.Fatalf("fake proc root: %v", err)
	}
	if _, err := ReadHostProcessCgroup(root, 0); err == nil {
		t.Fatal("PID 0 must fail")
	}
	if _, err := ReadHostProcessCgroup(root, uint32(pid)+1000000); err == nil {
		t.Fatal("a missing process must fail")
	}
}
