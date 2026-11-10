//go:build linux

package syftutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// These tests create real overlayfs markers the way containerd's overlay
// snapshotter does when it unpacks a layer: mknod for a whiteout, an xattr for
// an opaque directory. Both need root.

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("creating overlay whiteouts (mknod) needs root")
	}
}

// mknodChar creates a character device, skipping the test when the
// environment does not allow it (root without CAP_MKNOD, e.g. a container).
func mknodChar(t *testing.T, path string, dev uint64) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	if err := unix.Mknod(path, unix.S_IFCHR, int(dev)); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("mknod not permitted here: %v", err)
		}
		require.NoError(t, err)
	}
}

// writeWhiteout creates an overlayfs whiteout at path: a 0/0 character device.
func writeWhiteout(t *testing.T, path string) {
	t.Helper()
	mknodChar(t, path, 0)
}

// markOpaque sets xattr name=y on directory dir, skipping the test when the
// filesystem refuses it (the trusted namespace needs CAP_SYS_ADMIN, the user
// namespace needs tmpfs 6.6+ or a disk filesystem).
func markOpaque(t *testing.T, dir, name string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	if err := unix.Setxattr(dir, name, []byte("y"), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EPERM) {
			t.Skipf("%s not supported here: %v", name, err)
		}
		require.NoError(t, err)
	}
}

func Test_scanLayerMarkers_ReadsWhiteouts(t *testing.T) {
	requireRoot(t)
	layer := t.TempDir()
	writeWhiteout(t, filepath.Join(layer, "usr/local/lib/node_modules/npm"))
	writeWhiteout(t, filepath.Join(layer, "etc/old.conf"))
	// A character device that is not 0/0 is a real device node, not a whiteout.
	mknodChar(t, filepath.Join(layer, "null"), unix.Mkdev(1, 3))

	m, err := scanLayerMarkers(layer)
	require.NoError(t, err)
	assert.Equal(t, map[string]struct{}{
		"/usr/local/lib/node_modules/npm": {},
		"/etc/old.conf":                   {},
	}, m.whiteouts)
	assert.Empty(t, m.opaque)
}

func Test_scanLayerMarkers_ReadsOpaqueDirectories(t *testing.T) {
	requireRoot(t)
	for _, name := range opaqueXattrs {
		t.Run(name, func(t *testing.T) {
			layer := t.TempDir()
			markOpaque(t, filepath.Join(layer, "opt/app"), name)
			require.NoError(t, os.MkdirAll(filepath.Join(layer, "opt/other"), 0o755))

			m, err := scanLayerMarkers(layer)
			require.NoError(t, err)
			assert.Equal(t, map[string]struct{}{"/opt/app": {}}, m.opaque)
		})
	}
}

// Test_NewResolver_SBOMLeavesOutPackageWhitedOutByUpperLayer is the end-to-end
// case from the issue: a lower layer installs a package, a higher layer
// deletes its directory, and the SBOM built from the layer directories must
// not list it.
func Test_NewResolver_SBOMLeavesOutPackageWhitedOutByUpperLayer(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	top, base := filepath.Join(dir, "top"), filepath.Join(dir, "base")
	writePythonPkg(t, base, "usr/lib/python3/dist-packages", "kept-pkg")
	writePythonPkg(t, base, "usr/lib/python3/dist-packages", "removed-pkg")
	writeWhiteout(t, filepath.Join(top, "usr/lib/python3/dist-packages/removed-pkg-1.0.dist-info"))

	src, err := NewSource("test-image:latest", "sha256:digest", "test-image-id", testImageStatus(testDigests(2)), []string{top, base}, 1<<30)
	require.NoError(t, err)

	names := sbomPackageNames(t, src)
	assert.Contains(t, names, "kept-pkg")
	assert.NotContains(t, names, "removed-pkg")
}
