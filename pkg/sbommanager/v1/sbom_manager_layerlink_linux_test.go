//go:build linux

package v1

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/kubescape/node-agent/pkg/sbommanager/v1/syftutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// A whiteout in an upper CRI-O layer reached through <root>/l/<link> must
// still hide the file from the layer below it, so the l/<link> lowerdir has
// to reach the marker walk as the real layer directory.
func TestGetMountedVolumesCRIOLinkedLayerWhiteouts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating overlay whiteouts (mknod) needs root")
	}
	hostRoot := t.TempDir()
	overlay := "/var/lib/containers/storage/overlay"
	layer := func(id, link string) string {
		diff := filepath.Join(hostRoot, overlay, id, "diff")
		require.NoError(t, os.MkdirAll(diff, 0o755))
		require.NoError(t, os.MkdirAll(filepath.Join(hostRoot, overlay, "l"), 0o755))
		require.NoError(t, os.Symlink(filepath.Join("..", id, "diff"), filepath.Join(hostRoot, overlay, "l", link)))
		return diff
	}
	upper, lower := layer("bbbb", "UPPERLINK"), layer("aaaa", "LOWERLINK")
	require.NoError(t, os.MkdirAll(filepath.Join(lower, "etc"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(lower, "etc", "old.conf"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(lower, "etc", "kept.conf"), []byte("x"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(upper, "etc"), 0o755))
	if err := unix.Mknod(filepath.Join(upper, "etc", "old.conf"), unix.S_IFCHR, 0); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("mknod not permitted here: %v", err)
		}
		require.NoError(t, err)
	}

	s := writeMountInfo(t, hostRoot, "rw,lowerdir="+overlay+"/l/UPPERLINK:"+overlay+"/l/LOWERLINK,upperdir="+overlay+"/cccc/diff,workdir="+overlay+"/cccc/work")
	mounts, err := s.getMountedVolumes("123")
	require.NoError(t, err)
	require.Equal(t, []string{upper, lower}, mounts)

	_, imageStatus, imageTag, imageID := testNotifAndImageStatus()
	imageStatus.Info = map[string]string{"info": `{"imageSpec":{"rootfs":{"type":"layers","diff_ids":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}}}`}
	src, err := syftutil.NewSource(imageTag, imageID, imageID, imageStatus, mounts, 1024*1024)
	require.NoError(t, err)
	resolver, err := src.FileResolver(source.SquashedScope)
	require.NoError(t, err)
	kept, err := resolver.FilesByPath("/etc/kept.conf")
	require.NoError(t, err)
	require.Len(t, kept, 1)
	removed, err := resolver.FilesByPath("/etc/old.conf")
	require.NoError(t, err)
	require.Empty(t, removed, "the upper layer's whiteout must hide the lower file")
}
