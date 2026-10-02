package utils

import "testing"

// TestIsResolvedFullPath pins the boundary check on the gadget's "fpath"
// field. The non-absolute cases are real values captured from node-agent on a
// 2-node k3s cluster; each is a fragment of an unrelated event's path left in
// the gadget's per-CPU scratch buffer.
func TestIsResolvedFullPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// Stale scratch-buffer fragments -- must be rejected.
		{"observed fragment ocal.sh", "ocal.sh", false},
		{"observed fragment local.sh", "local.sh", false},
		{"observed fragment cal.sh", "cal.sh", false},
		{"observed fragment cksource", "cksource", false},
		{"empty", "", false},
		{"bare relative name", "passwd", false},
		{"relative with separator", "appendonlydir/appendonly.aof.1.incr.aof", false},
		{"dot", ".", false},

		// Legitimate resolved paths -- must be accepted.
		{"absolute file", "/etc/passwd", true},
		{"resolved symlink target", "/usr/lib/libtinfo.so.6.6", true},
		{"atomic writer target", "/health/..2026_08_03_16_47_11.8011833/ping_readiness_local.sh", true},
		{"headless proc, re-rooted later by NormalizePath", "/23240/setgroups", true},
		{"root", "/", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsResolvedFullPath(tt.path); got != tt.want {
				t.Errorf("IsResolvedFullPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestNormalizePathLaundersFragments documents the behaviour that made this
// defect invisible: NormalizePath turns a stale fragment into a well-formed
// absolute path. It is why the guard must run before NormalizePath, not
// inside it -- NormalizePath is also applied to "fname", which is
// legitimately relative for openat with a dirfd.
func TestNormalizePathLaundersFragments(t *testing.T) {
	for _, frag := range []string{"ocal.sh", "local.sh", "cksource"} {
		got := NormalizePath(frag)
		if got != "/"+frag {
			t.Fatalf("NormalizePath(%q) = %q, expected it to prefix a slash", frag, got)
		}
		if IsResolvedFullPath(frag) {
			t.Errorf("fragment %q must be rejected before NormalizePath sees it", frag)
		}
	}
}
