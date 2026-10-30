package igbackend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestFullLeaseHostInitStatus(t *testing.T) {
	good := "Name:\tsystemd\nPid:\t1\nTgid:\t1\nNSpid:\t1\nNStgid:\t1\n"
	require.NoError(t, validateHostInitStatus([]byte(good)))
	for name, bad := range map[string]string{
		"nested":    strings.Replace(good, "NSpid:\t1", "NSpid:\t99 1", 1),
		"other":     strings.Replace(good, "Pid:\t1", "Pid:\t2", 1),
		"missing":   strings.Replace(good, "NStgid:\t1\n", "", 1),
		"duplicate": good + "Pid: 1\n",
		"oversized": strings.Repeat("x", 65537),
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, validateHostInitStatus([]byte(bad))) })
	}
}
func TestFullLeaseHostPinsRejectForgedProcAndNamespaces(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "1"), 0700))
	pins, err := pinHostNamespaces(root)
	require.ErrorContains(t, err, "not procfs")
	require.Nil(t, pins)
	link := filepath.Join(t.TempDir(), "proc")
	require.NoError(t, os.Symlink("/proc", link))
	pins, err = pinHostNamespaces(link)
	require.Error(t, err)
	require.Nil(t, pins)
	file, err := os.CreateTemp(t.TempDir(), "not-namespace")
	require.NoError(t, err)
	defer file.Close()
	_, err = namespaceIdentity(file, unix.CLONE_NEWNS)
	require.ErrorContains(t, err, "not NSFS")
	_, err = namespaceIdentity(nil, unix.CLONE_NEWNS)
	require.Error(t, err)
}
func TestFullLeaseCurrentNamespaceType(t *testing.T) {
	f, err := os.Open("/proc/self/ns/mnt")
	if errors.Is(err, os.ErrPermission) {
		t.Skip("namespace handles require proc access")
	}
	require.NoError(t, err)
	defer f.Close()
	_, err = namespaceIdentity(f, unix.CLONE_NEWNS)
	require.NoError(t, err)
	_, err = namespaceIdentity(f, unix.CLONE_NEWPID)
	require.ErrorContains(t, err, "unexpected namespace type")
}
func TestFullLeaseSourceOwnershipAndClose(t *testing.T) {
	var closes atomic.Int32
	source := &ContainerdFullSource{source: fakeImageEvidenceSource{}, outstanding: 1, closeSource: func() error { closes.Add(1); return nil }}
	lease := &containerdFullLease{owner: source}
	require.ErrorContains(t, source.Close(), "still owns 1")
	require.Equal(t, int32(0), closes.Load())
	got, err := source.Prepare(context.Background(), sandboxpolicy.Binding{})
	require.ErrorContains(t, err, "closed")
	require.Nil(t, got)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); require.NoError(t, lease.Close()) }()
	}
	wg.Wait()
	require.Equal(t, uint64(0), source.outstanding)
	require.Equal(t, int32(0), closes.Load(), "lease must not close shared runtime client")
	require.NoError(t, source.Close())
	require.NoError(t, source.Close())
	require.Equal(t, int32(1), closes.Load())
}
func TestFullLeaseFailedPrepareReleasesReservation(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "1"), 0700))
	closes := 0
	source := &ContainerdFullSource{source: fakeImageEvidenceSource{}, validator: LinuxValidator{ProcRoot: root}, closeSource: func() error { closes++; return nil }}
	lease, err := source.Prepare(context.Background(), sandboxpolicy.Binding{})
	require.Error(t, err)
	require.Nil(t, lease)
	require.Zero(t, source.outstanding)
	require.NoError(t, source.Close())
	require.Equal(t, 1, closes)
}
func TestFullLeaseSourceCancellationAndCapacity(t *testing.T) {
	source := &ContainerdFullSource{source: fakeImageEvidenceSource{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lease, err := source.Prepare(ctx, sandboxpolicy.Binding{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, lease)
	require.Zero(t, source.outstanding)
	source.outstanding = FullBackendMaxBindings
	lease, err = source.Prepare(context.Background(), sandboxpolicy.Binding{})
	require.ErrorContains(t, err, "capacity")
	require.Nil(t, lease)
	require.Equal(t, uint64(FullBackendMaxBindings), source.outstanding)
}
func TestFullLeaseSourceCloseRetry(t *testing.T) {
	fault := errors.New("close runtime")
	source := &ContainerdFullSource{closeSource: func() error { return fault }}
	require.ErrorIs(t, source.Close(), fault)
	require.False(t, source.closed)
	require.True(t, source.closing)
	source.closeSource = func() error { return nil }
	require.NoError(t, source.Close())
	require.True(t, source.closed)
}
func TestFullLeaseOriginsAreBoundedSnapshots(t *testing.T) {
	image := &trustedImageLease{Complete: true, Inodes: []ImageInode{{Inode: 10, Major: 8, Minor: 1}}}
	snapshot, err := snapshotImageOrigins(image)
	require.NoError(t, err)
	image.Inodes[0].Inode = 11
	require.Equal(t, uint64(10), snapshot.Keys[0].Inode)
	lease := &containerdFullLease{origins: snapshot}
	received := lease.ImageOrigins()
	received.Keys[0].Inode = 12
	received.Complete = false
	require.Equal(t, uint64(10), lease.ImageOrigins().Keys[0].Inode)
	require.True(t, lease.ImageOrigins().Complete)
	image.Complete = false
	_, err = snapshotImageOrigins(image)
	require.Error(t, err)
	image.Complete = true
	image.Inodes = make([]ImageInode, 65537)
	_, err = snapshotImageOrigins(image)
	require.Error(t, err)
	require.NoError(t, lease.Close())
	require.Nil(t, lease.ImageOrigins())
	require.Error(t, lease.Check(context.Background()))
}
func TestFullLeaseImageContextInterruptionNotSticky(t *testing.T) {
	for _, fault := range []error{context.Canceled, context.DeadlineExceeded} {
		lease := &trustedImageLease{Complete: true, source: fakeImageEvidenceSource{err: fault}, process: &linuxLease{}}
		require.ErrorIs(t, lease.CheckContext(context.Background()), fault)
		require.True(t, lease.Complete)
		require.Nil(t, lease.failure)
	}
	fault := errors.New("runtime changed")
	lease := &trustedImageLease{Complete: true, source: fakeImageEvidenceSource{err: fault}, process: &linuxLease{}}
	require.ErrorIs(t, lease.CheckContext(context.Background()), fault)
	require.False(t, lease.Complete)
	require.ErrorIs(t, lease.failure, fault)
}
func TestFullLeaseCloseErrorConsumesAllPinsAndReservation(t *testing.T) {
	source := &ContainerdFullSource{outstanding: 1}
	closed, err := os.CreateTemp(t.TempDir(), "already-closed")
	require.NoError(t, err)
	require.NoError(t, closed.Close())
	process, err := os.CreateTemp(t.TempDir(), "process-pin")
	require.NoError(t, err)
	host, err := os.CreateTemp(t.TempDir(), "host-pin")
	require.NoError(t, err)
	lease := &containerdFullLease{owner: source, image: &trustedImageLease{root: closed}, process: &linuxLease{proc: process}, host: &hostNamespacePins{mount: host}}
	require.Error(t, lease.Close())
	require.Zero(t, source.outstanding)
	require.True(t, lease.closed)
	require.Nil(t, lease.image)
	require.Nil(t, lease.process)
	require.Nil(t, lease.host)
	_, err = process.Stat()
	require.ErrorIs(t, err, os.ErrClosed)
	_, err = host.Stat()
	require.ErrorIs(t, err, os.ErrClosed)
	require.NoError(t, lease.Close())
	require.NoError(t, source.Close())
}

func TestFullLeaseConstructorRejectsInvalidAdminPaths(t *testing.T) {
	for _, paths := range [][3]string{{"relative", "/proc", "/sys/fs/cgroup"}, {"/", "relative", "/sys/fs/cgroup"}, {"/", "/proc", "/sys/../sys/fs/cgroup"}} {
		source, err := NewContainerdFullSource("/nonexistent/socket", paths[0], paths[1], paths[2], ImageIndexLimits{})
		require.ErrorContains(t, err, "canonical")
		require.Nil(t, source)
	}
	source, err := NewContainerdFullSource("/nonexistent/socket", "/", "/proc", "/sys/fs/cgroup", ImageIndexLimits{Files: -1})
	require.ErrorContains(t, err, "budget")
	require.Nil(t, source)
}

func TestFullLeaseIndexCheckPreservesCallerDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	index := &lowerIndexLease{}
	require.ErrorIs(t, index.CheckContext(ctx), context.Canceled)
}

// Built-in types let the IG consumer select this additive contract without a pin
// update merely to expose the provider method.
var _ interface{ SharedContainerName() (string, error) } = (*containerdFullLease)(nil)

type sharedNameNoRPCSource struct{}

func (sharedNameNoRPCSource) Evidence(context.Context, string) (containerdImageEvidence, error) {
	panic("SharedContainerName must not observe the runtime")
}

func sharedNameLease(binding sandboxpolicy.Binding) *containerdFullLease {
	return &containerdFullLease{
		process: &linuxLease{identity: binding},
		image:   &trustedImageLease{source: sharedNameNoRPCSource{}},
		host:    &hostNamespacePins{},
	}
}

func TestFullLeaseSharedContainerNameDomain(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		valid       bool
	}{
		{"ordinary", "application", true},
		{"exact-255", strings.Repeat("a", 255), true},
		{"over-256", strings.Repeat("a", 256), false},
		{"utf8-exact", strings.Repeat("é", 127) + "a", true},
		{"utf8-over", strings.Repeat("é", 128), false},
		{"empty", "", false},
		{"nul", "app\x00name", false},
		{"invalid-utf8", "app\xff", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease := sharedNameLease(sandboxpolicy.Binding{ContainerName: tc.value})
			got, err := lease.SharedContainerName()
			if tc.valid {
				require.NoError(t, err)
				require.Equal(t, tc.value, got)
			} else {
				require.Error(t, err)
				require.Empty(t, got)
			}
		})
	}
}

func TestFullLeaseSharedContainerNameAvailability(t *testing.T) {
	for _, kind := range []string{"closing", "closed", "process", "image", "host"} {
		t.Run(kind, func(t *testing.T) {
			lease := sharedNameLease(sandboxpolicy.Binding{ContainerName: "application"})
			switch kind {
			case "closing":
				lease.closing = true
			case "closed":
				lease.closed = true
			case "process":
				lease.process = nil
			case "image":
				lease.image = nil
			case "host":
				lease.host = nil
			}
			got, err := lease.SharedContainerName()
			require.ErrorContains(t, err, "unavailable")
			require.Empty(t, got)
		})
	}
}

func TestFullLeaseSharedContainerNameRetainsOriginalBinding(t *testing.T) {
	binding := sandboxpolicy.Binding{ContainerName: "original"}
	lease := sharedNameLease(binding)
	binding.ContainerName = "replacement"
	got, err := lease.SharedContainerName()
	require.NoError(t, err)
	require.Equal(t, "original", got)
	require.NoError(t, lease.Close())
	require.Equal(t, "original", got, "borrowed immutable string survives caller retention")
	got, err = lease.SharedContainerName()
	require.ErrorContains(t, err, "unavailable")
	require.Empty(t, got)
}

func TestFullLeaseSharedContainerNameJoinsClose(t *testing.T) {
	lease := sharedNameLease(sandboxpolicy.Binding{ContainerName: "original"})
	var wg sync.WaitGroup
	var inconsistent atomic.Bool
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			for range 100 {
				got, err := lease.SharedContainerName()
				if (err == nil && got != "original") || (err != nil && got != "") {
					inconsistent.Store(true)
				}
			}
		})
	}
	close(start)
	require.NoError(t, lease.Close())
	wg.Wait()
	require.False(t, inconsistent.Load())
	got, err := lease.SharedContainerName()
	require.Error(t, err)
	require.Empty(t, got)
}
