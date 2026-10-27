package igbackend

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func indexFixture(t *testing.T) (string, string) {
	t.Helper()
	root, err := os.MkdirTemp("/dev/shm", "ig-lower-index-")
	if err != nil {
		t.Skipf("tmpfs fixture unavailable: %v", err)
	}
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(root)) })
	lower := filepath.Join(root, "layer")
	require.NoError(t, os.Mkdir(lower, 0700))
	return root, lower
}
func indexFiles(t *testing.T, lower string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(lower, "plain"), []byte("not executable"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(lower, "exec"), []byte("executable"), 0700))
}
func descriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(entries)
}
func TestLowerIndexAllRegularAndNoSymlinkTraversal(t *testing.T) {
	root, lower := indexFixture(t)
	indexFiles(t, lower)
	require.NoError(t, os.Link(filepath.Join(lower, "plain"), filepath.Join(lower, "hardlink")))
	require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(lower, "escape")))
	require.NoError(t, os.Symlink("/does/not/exist", filepath.Join(lower, "dangling")))
	require.NoError(t, unix.Mkfifo(filepath.Join(lower, "fifo"), 0600))
	lease, err := buildLowerIndex(context.Background(), root, []string{"/layer"}, ImageIndexLimits{})
	require.NoError(t, err)
	defer lease.Close()
	require.True(t, lease.Complete)
	require.Len(t, lease.Inodes, 2)
	require.NoError(t, lease.Check())
	require.NoError(t, lease.Close())
	require.NoError(t, lease.Close())
	require.False(t, lease.Complete)
	require.Error(t, lease.Check())
}
func TestLowerIndexMutations(t *testing.T) {
	for _, kind := range []string{"write", "chmod", "create", "remove", "replace-root", "rename-subdir"} {
		t.Run(kind, func(t *testing.T) {
			root, lower := indexFixture(t)
			indexFiles(t, lower)
			require.NoError(t, os.Mkdir(filepath.Join(lower, "sub"), 0700))
			require.NoError(t, os.WriteFile(filepath.Join(lower, "sub", "nested"), []byte("data"), 0600))
			lease, err := buildLowerIndex(context.Background(), root, []string{"/layer"}, ImageIndexLimits{})
			require.NoError(t, err)
			defer lease.Close()
			switch kind {
			case "write":
				require.NoError(t, os.WriteFile(filepath.Join(lower, "plain"), []byte("changed"), 0600))
			case "chmod":
				require.NoError(t, os.Chmod(filepath.Join(lower, "plain"), 0700))
			case "create":
				require.NoError(t, os.WriteFile(filepath.Join(lower, "new"), nil, 0600))
			case "remove":
				require.NoError(t, os.Remove(filepath.Join(lower, "exec")))
			case "replace-root":
				require.NoError(t, os.Rename(lower, lower+"-old"))
				require.NoError(t, os.Mkdir(lower, 0700))
			case "rename-subdir":
				require.NoError(t, os.Rename(filepath.Join(lower, "sub"), filepath.Join(lower, "other")))
			}
			require.Error(t, lease.Check())
		})
	}
}
func TestLowerIndexBudgetsAndFailureCleanup(t *testing.T) {
	root, lower := indexFixture(t)
	indexFiles(t, lower)
	require.NoError(t, os.MkdirAll(filepath.Join(lower, "a", "b"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(lower, "a", "b", "c"), nil, 0600))
	baseline := descriptorCount(t)
	cases := []struct {
		names  []string
		limits ImageIndexLimits
	}{
		{[]string{"/layer"}, ImageIndexLimits{Files: 1}},
		{[]string{"/layer"}, ImageIndexLimits{Entries: 1}},
		{[]string{"/layer"}, ImageIndexLimits{Depth: 1}},
		{[]string{"/layer"}, ImageIndexLimits{PathBytes: 7}},
		{[]string{"/layer", "/missing"}, ImageIndexLimits{}},
		{[]string{"/layer", "/other"}, ImageIndexLimits{Roots: 1}},
		{[]string{"/layer", "/layer"}, ImageIndexLimits{}},
		{[]string{"/../layer"}, ImageIndexLimits{}},
		{[]string{"layer"}, ImageIndexLimits{}},
		{[]string{"/"}, ImageIndexLimits{}},
		{nil, ImageIndexLimits{}},
		{[]string{"/layer"}, ImageIndexLimits{Files: 65537}},
		{[]string{"/layer"}, ImageIndexLimits{Roots: -1}},
	}
	for _, tc := range cases {
		lease, err := buildLowerIndex(context.Background(), root, tc.names, tc.limits)
		require.Error(t, err)
		require.Nil(t, lease)
		require.Equal(t, baseline, descriptorCount(t))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lease, err := buildLowerIndex(ctx, root, []string{"/layer"}, ImageIndexLimits{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, lease)
	require.Equal(t, baseline, descriptorCount(t))
}
func TestLowerIndexRejectsSymlinkRoots(t *testing.T) {
	root, lower := indexFixture(t)
	require.NoError(t, os.Symlink(lower, filepath.Join(root, "alias")))
	baseline := descriptorCount(t)
	lease, err := buildLowerIndex(context.Background(), root, []string{"/alias"}, ImageIndexLimits{})
	require.Error(t, err)
	require.Nil(t, lease)
	lease, err = buildLowerIndex(context.Background(), filepath.Join(root, "alias"), []string{"/child"}, ImageIndexLimits{})
	require.Error(t, err)
	require.Nil(t, lease)
	require.Equal(t, baseline, descriptorCount(t))
}
func TestLowerIndexRejectsOverlay(t *testing.T) {
	root := t.TempDir()
	var fs unix.Statfs_t
	require.NoError(t, unix.Statfs(root, &fs))
	if fs.Type != unix.OVERLAYFS_SUPER_MAGIC {
		t.Skip("fixture filesystem is not overlay")
	}
	lower := filepath.Join(root, "layer")
	require.NoError(t, os.Mkdir(lower, 0700))
	lease, err := buildLowerIndex(context.Background(), root, []string{"/layer"}, ImageIndexLimits{})
	require.ErrorContains(t, err, "unsupported lower filesystem")
	require.Nil(t, lease)
}
func TestLowerIndexMultiLayerDedupAndLeaseCleanup(t *testing.T) {
	root, lower := indexFixture(t)
	indexFiles(t, lower)
	second := filepath.Join(root, "other")
	require.NoError(t, os.Mkdir(second, 0700))
	require.NoError(t, os.Link(filepath.Join(lower, "plain"), filepath.Join(second, "linked")))
	before := descriptorCount(t)
	lease, err := buildLowerIndex(context.Background(), root, []string{"/layer", "/other"}, ImageIndexLimits{})
	require.NoError(t, err)
	require.Len(t, lease.Inodes, 2)
	require.Equal(t, before+3, descriptorCount(t))
	require.NoError(t, lease.Close())
	require.Equal(t, before, descriptorCount(t))
}

type cancelDuringIndex struct {
	context.Context
	calls int
}

func (c *cancelDuringIndex) Err() error {
	c.calls++
	if c.calls >= 10 {
		return context.Canceled
	}
	return nil
}
func TestLowerIndexCancellationDuringWalk(t *testing.T) {
	root, lower := indexFixture(t)
	indexFiles(t, lower)
	before := descriptorCount(t)
	ctx := &cancelDuringIndex{Context: context.Background()}
	lease, err := buildLowerIndex(ctx, root, []string{"/layer"}, ImageIndexLimits{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, lease)
	require.Equal(t, before, descriptorCount(t))
}
func TestLowerIndexHostRootReplacement(t *testing.T) {
	root, lower := indexFixture(t)
	indexFiles(t, lower)
	lease, err := buildLowerIndex(context.Background(), root, []string{"/layer"}, ImageIndexLimits{})
	require.NoError(t, err)
	defer lease.Close()
	moved := root + "-moved"
	require.NoError(t, os.Rename(root, moved))
	defer os.RemoveAll(moved)
	require.NoError(t, os.Mkdir(root, 0700))
	require.ErrorContains(t, lease.Check(), "host root identity changed")
}

func TestLowerIndexRejectsUnsupportedFilesystem(t *testing.T) {
	lease, err := buildLowerIndex(context.Background(), "/", []string{"/proc"}, ImageIndexLimits{})
	require.ErrorContains(t, err, "unsupported lower filesystem")
	require.Nil(t, lease)
}
