package igbackend

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// This is an optional real containerd root-discovery proof, not a host test.
// Provision a disposable k8s.io namespace task first, with an exact 64-hex ID.
// The task must use io.containerd.runc.v2, drop CAP_SYS_CHROOT from every
// capability set, and use canonicalRootSeccomp's exact native-x86_64 errno
// barrier. Default OCI capabilities/seccomp do NOT satisfy this matrix.
// The fixture never creates, deletes or mutates containers or mount namespaces.
func TestContainerdImageEvidenceKernel(t *testing.T) {
	if os.Getenv("IG_IMAGE_EVIDENCE_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable containerd guest opt-in required")
	}
	socket := os.Getenv("IG_IMAGE_EVIDENCE_SOCKET")
	if socket == "" {
		socket = "/run/containerd/containerd.sock"
	}
	id := os.Getenv("IG_IMAGE_EVIDENCE_CONTAINER_ID")
	require.True(t, fullContainerID(id))
	source, err := newContainerdImageSource(socket)
	require.NoError(t, err)
	defer source.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	evidence, err := source.Evidence(ctx, id)
	require.NoError(t, err)
	bytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", evidence.PID))
	require.NoError(t, err)
	var cg string
	for _, line := range strings.Split(string(bytes), "\n") {
		if strings.HasPrefix(line, "0::") {
			cg = strings.TrimPrefix(line, "0::")
		}
	}
	require.NotEmpty(t, cg)
	require.NotEqual(t, "/", cg)
	var cgroup, mountns unix.Stat_t
	require.NoError(t, unix.Stat("/sys/fs/cgroup"+cg, &cgroup))
	require.NoError(t, unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", evidence.PID), &mountns))
	binding := sandboxpolicy.Binding{Runtime: "containerd", ContainerID: id, PID: evidence.PID, CgroupID: cgroup.Ino, CgroupPath: cg, MountNamespace: mountns.Ino}
	process, err := (LinuxValidator{}).Acquire(ctx, binding)
	require.NoError(t, err)
	defer process.Close()
	lease, err := acquireImageEvidence(ctx, source, process.(*linuxLease), "/", ImageIndexLimits{})
	require.NoError(t, err)
	defer lease.Close()
	require.True(t, lease.Complete)
	require.NotEmpty(t, lease.Inodes)
	require.NoError(t, lease.Check())
	t.Logf("trusted containerd root/index validated: id=%s pid=%d inodes=%d rootMount=%d", id, binding.PID, len(lease.Inodes), lease.rootEvidence.MountID)
	require.NoError(t, lease.Close())
	require.NoError(t, lease.Close())
	require.Error(t, lease.Check())
}

// This optional proof exercises the production combined adapter, including host
// namespace authentication and client/lease ownership. It does not attach the
// enforcer: the full native integration requires a separate proof.
func TestContainerdFullLeaseKernel(t *testing.T) {
	if os.Getenv("IG_IMAGE_EVIDENCE_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable containerd guest opt-in required")
	}
	socket := os.Getenv("IG_IMAGE_EVIDENCE_SOCKET")
	if socket == "" {
		socket = "/run/containerd/containerd.sock"
	}
	id := os.Getenv("IG_IMAGE_EVIDENCE_CONTAINER_ID")
	require.True(t, fullContainerID(id))
	source, err := NewContainerdFullSource(socket, "/", "/proc", "/sys/fs/cgroup", ImageIndexLimits{})
	require.NoError(t, err)
	defer source.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	evidence, err := source.source.Evidence(ctx, id)
	require.NoError(t, err)
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", evidence.PID))
	require.NoError(t, err)
	var cg string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			cg = strings.TrimPrefix(line, "0::")
		}
	}
	require.NotEmpty(t, cg)
	require.NotEqual(t, "/", cg)
	var cgroup, mountns unix.Stat_t
	require.NoError(t, unix.Stat("/sys/fs/cgroup"+cg, &cgroup))
	require.NoError(t, unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", evidence.PID), &mountns))
	binding := sandboxpolicy.Binding{Runtime: "containerd", ContainerID: id, PID: evidence.PID, CgroupID: cgroup.Ino, CgroupPath: cg, MountNamespace: mountns.Ino}
	lease, err := source.Prepare(ctx, binding)
	require.NoError(t, err)
	defer lease.Close()
	require.NoError(t, lease.Check(ctx))
	require.NotNil(t, lease.InitProc())
	require.NotNil(t, lease.Cgroup())
	require.NotNil(t, lease.MountNamespace())
	require.NotNil(t, lease.HostMountNamespace())
	origins := lease.ImageOrigins()
	require.NotNil(t, origins)
	require.True(t, origins.Complete)
	require.NotEmpty(t, origins.Keys)
	// Client shutdown cannot race lease ownership; a refused close seals new
	// admissions but must not invalidate already acquired evidence.
	require.Error(t, source.Close())
	require.NoError(t, lease.Check(ctx))
	proc := lease.InitProc()
	require.NoError(t, lease.Close())
	require.NoError(t, lease.Close())
	require.Error(t, lease.Check(ctx))
	require.Equal(t, ^uintptr(0), proc.Fd())
	require.NoError(t, source.Close())
	require.NoError(t, source.Close())
	t.Logf("combined trusted lease validated: id=%s pid=%d origins=%d", id, binding.PID, len(origins.Keys))
}
