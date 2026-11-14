package igbackend

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
)

// EKS run 13: with hostPath / mounted at /host without mount propagation, the
// pod's sandbox /dev/shm tmpfs (mounted by containerd after node-agent
// started) is invisible through /host, so its bind fails the inode check.
func TestHostRootPropagation(t *testing.T) {
	const root = "1 0 259:1 / / rw,relatime shared:1 - xfs /dev/nvme0n1p1 rw\n"
	const overlay = "2000 1990 0:300 / / rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w\n"
	host := func(tags string) string {
		return "2010 2000 259:1 / /host rw,relatime " + tags + "- xfs /dev/nvme0n1p1 rw\n"
	}
	for _, tt := range []struct {
		name, mountinfo, hostRoot, want string
	}{
		{"eks-none-default", overlay + host(""), "/host", "host root /host (mount /host) does not receive host mount propagation; set mountPropagation: HostToContainer on the host root volumeMount"},
		{"host-to-container", overlay + host("master:1 "), "/host", ""},
		{"bidirectional", overlay + host("shared:7 master:1 "), "/host", ""},
		{"stacked-private-on-top", overlay + host("master:1 ") + "2020 2010 0:301 / /host rw - tmpfs tmpfs rw\n", "/host", "host root /host (mount /host) does not receive host mount propagation; set mountPropagation: HostToContainer on the host root volumeMount"},
		{"covered-by-parent", root + "30 1 0:30 / /var rw shared:2 - xfs /dev/x rw\n", "/var/host", ""},
		{"vm-host-root", root, "/", ""},
		{"private-root", overlay, "/", "host root / (mount /) does not receive host mount propagation; set mountPropagation: HostToContainer on the host root volumeMount"},
		{"sibling-prefix-ignored", overlay + "2010 2000 259:1 / /ho rw master:1 - xfs /dev/x rw\n", "/host", "host root /host (mount /) does not receive host mount propagation; set mountPropagation: HostToContainer on the host root volumeMount"},
		{"malformed", "1 0 259:1 / / rw\n", "/host", "malformed self mountinfo"},
		{"relative", root, "host", "canonical host root required"},
		{"space", root, "/host root", "canonical host root required"},
		{"tab", root, "/host\troot", "canonical host root required"},
		{"newline", root, "/host\nroot", "canonical host root required"},
		{"backslash", root + "40 1 0:40 / /host\\040x rw master:1 - xfs /dev/x rw\n", "/host\\040x", "canonical host root required"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHostRootPropagation([]byte(tt.mountinfo), tt.hostRoot)
			if tt.want == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.want)
		})
	}
}

func TestBindSourceClassNeverLeaksPaths(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for source, want := range map[string]string{
		"/run/containerd/io.containerd.grpc.v1.cri/sandboxes/" + id + "/shm":          "containerd sandbox shm",
		"/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/" + id + "/hostname": "containerd sandbox file",
		"/var/lib/kubelet/pods/uid/volumes/kubernetes.io~projected/kube-api-access-x": "kubelet projected volume",
		"/var/lib/kubelet/pods/uid/volumes/kubernetes.io~secret/token":                "kubelet secret volume",
		"/var/lib/kubelet/pods/uid/volumes/kubernetes.io~configmap/probe":             "kubelet configmap volume",
		"/var/lib/kubelet/pods/uid/volumes/kubernetes.io~downward-api/podinfo":        "kubelet downward-api volume",
		"/var/lib/kubelet/pods/uid/volumes/Weird~Plugin/x":                            "kubelet volume",
		"/var/lib/kubelet/pods/uid/etc-hosts":                                         "kubelet etc-hosts",
		"/var/lib/kubelet/pods/uid/containers/probe/abc":                              "kubelet container file",
		"/var/lib/kubelet/pods/uid/plugins/x":                                         "kubelet pod path",
		"/data/customer-secret-name":                                                  "host path",
	} {
		require.Equal(t, want, bindSourceClass(source, id), source)
	}
}

func TestBindInodeMismatchesAreAggregated(t *testing.T) {
	hostRoot, containerRoot, proc := t.TempDir(), t.TempDir(), t.TempDir()
	for _, dir := range []string{filepath.Join(hostRoot, "data/a"), filepath.Join(hostRoot, "data/b"), filepath.Join(containerRoot, "a"), filepath.Join(containerRoot, "b")} {
		require.NoError(t, os.MkdirAll(dir, 0o700))
	}
	require.NoError(t, os.WriteFile(filepath.Join(proc, "mountinfo"), []byte("1 0 0:1 / / rw - tmpfs tmpfs rw\n"), 0o600))
	open := func(p string) *os.File {
		f, err := os.Open(p)
		require.NoError(t, err)
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	evidence := containerdImageEvidence{Spec: &specs.Spec{Mounts: []specs.Mount{
		{Type: "bind", Source: "/data/a", Destination: "/a", Options: []string{"rbind", "rw"}},
		{Type: "bind", Source: "/data/b", Destination: "/b", Options: []string{"rbind", "rw"}},
	}}}
	err := validateBindVolumes(context.Background(), evidence, &lowerIndexLease{host: open(hostRoot)}, open(containerRoot), &linuxLease{proc: open(proc)})
	require.EqualError(t, err, "bind source/destination inode mismatch at \"/a\" (source: host path)\nbind source/destination inode mismatch at \"/b\" (source: host path)")
}

func TestBindInodeMismatchJoinsLaterRefusals(t *testing.T) {
	// One tree serves as both host and container root, so a bind whose source
	// and destination are the same directory genuinely matches.
	tree, proc := t.TempDir(), t.TempDir()
	for _, dir := range []string{"data/a", "a", "data/same"} {
		require.NoError(t, os.MkdirAll(filepath.Join(tree, dir), 0o700))
	}
	var sx unix.Statx_t
	require.NoError(t, unix.Statx(unix.AT_FDCWD, filepath.Join(tree, "data/same"), 0, unix.STATX_MNT_ID, &sx))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "mountinfo"), []byte(fmt.Sprintf("%d 1 0:1 / / ro - tmpfs tmpfs rw\n", sx.Mnt_id)), 0o600))
	open := func(p string) *os.File {
		f, err := os.Open(p)
		require.NoError(t, err)
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	run := func(mounts ...specs.Mount) error {
		evidence := containerdImageEvidence{Spec: &specs.Spec{Mounts: mounts}}
		return validateBindVolumes(context.Background(), evidence, &lowerIndexLease{host: open(tree)}, open(tree), &linuxLease{proc: open(proc)})
	}
	mismatch := specs.Mount{Type: "bind", Source: "/data/a", Destination: "/a", Options: []string{"rbind", "ro"}}
	same := specs.Mount{Type: "bind", Source: "/data/same", Destination: "/data/same", Options: []string{"rbind", "ro"}}
	require.NoError(t, run(same), "control: a matching bind is accepted")

	// (a) A later, different refusal is reported together with the mismatch.
	err := run(mismatch, specs.Mount{Type: "bind", Source: "/etc/passwd", Destination: "/etc/passwd", Options: []string{"rbind", "ro"}})
	require.EqualError(t, err, "bind source/destination inode mismatch at \"/a\" (source: host path)\nbind source exposes sensitive host/runtime/lower roots; no authenticated sandbox-mount provenance")
	err = run(mismatch, specs.Mount{Type: "bind", Source: "/data/same", Destination: "/missing", Options: []string{"rbind", "ro"}})
	require.ErrorContains(t, err, "inode mismatch at \"/a\"")
	require.ErrorIs(t, err, os.ErrNotExist)

	// (b) A later matching bind does not clear an earlier mismatch.
	require.EqualError(t, run(mismatch, same), "bind source/destination inode mismatch at \"/a\" (source: host path)")
}
