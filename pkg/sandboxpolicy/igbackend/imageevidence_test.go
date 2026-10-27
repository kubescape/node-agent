package igbackend

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/errdefs"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/opencontainers/go-digest"
	imageidentity "github.com/opencontainers/image-spec/identity"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func goodImageEvidence() containerdImageEvidence {
	diff := digest.FromString("layer")
	chain := imageidentity.ChainID([]digest.Digest{diff}).String()
	return containerdImageEvidence{Namespace: "k8s.io", RuntimeName: "io.containerd.runc.v2", ID: strings.Repeat("a", 64), Image: "registry/image@sha256:" + strings.Repeat("b", 64), Snapshotter: "overlayfs", SnapshotKey: "active", PID: 42, Running: true,
		Spec:    &specs.Spec{Root: &specs.Root{Path: "rootfs"}, Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{Bounding: []string{"CAP_CHOWN"}}}, Linux: &specs.Linux{Seccomp: canonicalRootSeccomp(), Namespaces: []specs.LinuxNamespace{{Type: specs.MountNamespace}, {Type: specs.PIDNamespace}}}},
		DiffIDs: []digest.Digest{diff}, Active: snapshots.Info{Name: "active", Kind: snapshots.KindActive, Parent: chain}, Parents: []snapshots.Info{{Name: chain, Kind: snapshots.KindCommitted}},
		Mounts: []mount.Mount{{Type: "overlay", Source: "overlay", Options: []string{"lowerdir=/snapshots/1/fs", "upperdir=/snapshots/2/fs", "workdir=/snapshots/2/work"}}}}
}

type fakeImageEvidenceSource struct {
	evidence containerdImageEvidence
	err      error
}

func (f fakeImageEvidenceSource) Evidence(ctx context.Context, _ string) (containerdImageEvidence, error) {
	if err := ctx.Err(); err != nil {
		return containerdImageEvidence{}, err
	}
	return f.evidence, f.err
}
func TestContainerdImageEvidenceRejectsForgedInputs(t *testing.T) {
	tests := map[string]func(*containerdImageEvidence){
		"namespace": func(e *containerdImageEvidence) { e.Namespace = "default" }, "id": func(e *containerdImageEvidence) { e.ID = strings.Repeat("b", 64) }, "pid": func(e *containerdImageEvidence) { e.PID++ }, "stopped": func(e *containerdImageEvidence) { e.Running = false },
		"spec": func(e *containerdImageEvidence) { e.Spec = nil }, "snapshotter": func(e *containerdImageEvidence) { e.Snapshotter = "native" }, "active-kind": func(e *containerdImageEvidence) { e.Active.Kind = snapshots.KindCommitted }, "active-name": func(e *containerdImageEvidence) { e.Active.Name = "other" }, "active-parent": func(e *containerdImageEvidence) { e.Active.Parent = "other" },
		"parent-kind": func(e *containerdImageEvidence) { e.Parents[0].Kind = snapshots.KindActive }, "parent-chain": func(e *containerdImageEvidence) { e.Parents[0].Parent = "cycle" }, "parent-name": func(e *containerdImageEvidence) { e.Parents[0].Name = "wrong" }, "diff-id": func(e *containerdImageEvidence) { e.DiffIDs[0] = "invalid" }, "chain-budget": func(e *containerdImageEvidence) { e.DiffIDs = make([]digest.Digest, 129) },
		"root": func(e *containerdImageEvidence) { e.Spec.Root.Path = "../outside" }, "mount-spec": func(e *containerdImageEvidence) { e.Mounts[0].Type = "bind" }, "mount-options": func(e *containerdImageEvidence) { e.Mounts[0].Options = append(e.Mounts[0].Options, "redirect_dir=on") }, "mount-layers": func(e *containerdImageEvidence) { e.Mounts[0].Options[0] = "lowerdir=/a:/b" },
		"host-pid": func(e *containerdImageEvidence) { e.Spec.Linux.Namespaces[1].Path = "/proc/1/ns/pid" }, "host-mount": func(e *containerdImageEvidence) { e.Spec.Linux.Namespaces[0].Path = "/proc/1/ns/mnt" }, "missing-ns": func(e *containerdImageEvidence) { e.Spec.Linux.Namespaces = nil },
		"sysadmin": func(e *containerdImageEvidence) { e.Spec.Process.Capabilities.Bounding = []string{"CAP_SYS_ADMIN"} }, "checkpoint": func(e *containerdImageEvidence) {
			e.Spec.Process.Capabilities.Ambient = []string{"CAP_CHECKPOINT_RESTORE"}
		}, "block": func(e *containerdImageEvidence) { e.Spec.Linux.Devices = []specs.LinuxDevice{{Type: "b", Major: 8}} }, "privileged": func(e *containerdImageEvidence) {
			e.Spec.Linux.Resources = &specs.LinuxResources{Devices: []specs.LinuxDeviceCgroup{{Allow: true}}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			e := goodImageEvidence()
			mutate(&e)
			_, err := validateContainerdEvidence(e, strings.Repeat("a", 64), 42)
			require.Error(t, err)
			// Rejection occurs before any process root/index can be marked Complete.
			process := &linuxLease{identity: sandboxpolicy.Binding{Runtime: "containerd", ContainerID: strings.Repeat("a", 64), PID: 42}}
			lease, err := acquireImageEvidence(context.Background(), fakeImageEvidenceSource{evidence: e}, process, "/", ImageIndexLimits{})
			require.Error(t, err)
			require.Nil(t, lease)
		})
	}
	e := goodImageEvidence()
	overlay, err := validateContainerdEvidence(e, e.ID, e.PID)
	require.NoError(t, err)
	require.Equal(t, []string{"/snapshots/1/fs"}, overlay.Lower)
}
func TestOverlayEvidenceStrictSyntax(t *testing.T) {
	for _, option := range []string{"lowerdir=relative", "lowerdir=/a::/b", "lowerdir=/a\\040b", "lowerdir=/a/../b", "lowerdir=/a%2fb", "lowerdir=/a:/a", "lowerdir=/snapshots/2/fs", "upperdir=/a,b", "redirect_dir=on", "data-only=/a", "metacopy=maybe", "unknown=1"} {
		options := []string{"lowerdir=/snapshots/1/fs", "upperdir=/snapshots/2/fs", "workdir=/snapshots/2/work"}
		key, _, _ := strings.Cut(option, "=")
		replaced := false
		for i, old := range options {
			if strings.HasPrefix(old, key+"=") {
				options[i] = option
				replaced = true
			}
		}
		if !replaced {
			options = append(options, option)
		}
		_, err := parseOverlayEvidence(options)
		require.Error(t, err, option)
	}
}
func TestPinnedRootMountEvidence(t *testing.T) {
	good := "123 2 0:7 / / rw,relatime - overlay overlay rw,lowerdir=/a,upperdir=/b,workdir=/c\n"
	root, err := parseProcessRootEvidence([]byte(good), 123)
	require.NoError(t, err)
	require.Equal(t, "/b", root.Upper)
	for _, data := range []string{strings.Replace(good, " / / ", " /subtree / ", 1), strings.Replace(good, " / / ", " / /elsewhere ", 1), strings.Replace(good, "- overlay overlay", "- ext4 disk", 1), good + good, "broken", strings.Repeat("x", 65537)} {
		_, err := parseProcessRootEvidence([]byte(data), 123)
		require.Error(t, err)
	}
	_, err = parseProcessRootEvidence([]byte(good), 124)
	require.Error(t, err)
	require.False(t, sameOverlay(root, overlayEvidence{Lower: []string{"/forged"}, Upper: "/b", Work: "/c"}))
}
func TestImageEvidenceCancellationAndSourceFailure(t *testing.T) {
	process := &linuxLease{identity: sandboxpolicy.Binding{Runtime: "containerd", ContainerID: strings.Repeat("a", 64), PID: 42}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lease, err := acquireImageEvidence(ctx, fakeImageEvidenceSource{}, process, "/", ImageIndexLimits{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, lease)
	fault := errors.New("runtime unavailable")
	lease, err = acquireImageEvidence(context.Background(), fakeImageEvidenceSource{err: fault}, process, "/", ImageIndexLimits{})
	require.ErrorIs(t, err, fault)
	require.Nil(t, lease)
}
func TestVolumePolicyAndAliasChecks(t *testing.T) {
	e := goodImageEvidence()
	e.Spec.Mounts = []specs.Mount{{Type: "bind", Source: "/var/lib/kubelet/pods/uid/hosts", Destination: "/etc/hosts", Options: []string{"rbind", "rw"}}, {Type: "bind", Source: "/var/lib/kubelet/pods/uid/projected", Destination: "/var/run/secrets/kubernetes.io/serviceaccount", Options: []string{"rbind", "ro"}}}
	require.NoError(t, validateImageSpec(e.Spec))
	for _, source := range []string{"/etc", "/etc/passwd", "/run/containerd/containerd.sock", "/var/lib/containerd", "/snapshots/1/fs", "/snapshots"} {
		require.True(t, sensitiveVolumeSource(source, []lowerLayer{{name: "/snapshots/1/fs"}}), source)
	}
	require.False(t, sensitiveVolumeSource("/var/lib/kubelet/pods/uid/volume", []lowerLayer{{name: "/snapshots/1/fs"}}))
	root, lower := indexFixture(t)
	indexFiles(t, lower)
	file, err := os.Open(filepath.Join(lower, "plain"))
	require.NoError(t, err)
	defer file.Close()
	stat, err := indexStat(file)
	require.NoError(t, err)
	key := ImageInode{stat.Ino, unix.Major(stat.Dev), unix.Minor(stat.Dev)}
	walker := volumeWalker{ctx: context.Background(), lower: map[ImageInode]bool{key: true}, writable: true}
	require.ErrorContains(t, walker.walk(file, "/", 0, sha256.New()), "aliases")
	walker.writable = false
	require.NoError(t, walker.walk(file, "/", 0, sha256.New()))
	projected := filepath.Join(root, "projected")
	require.NoError(t, os.MkdirAll(filepath.Join(projected, "..version"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(projected, "..version", "token"), []byte("token"), 0600))
	require.NoError(t, os.Symlink("..version", filepath.Join(projected, "..data")))
	require.NoError(t, os.Symlink("..data/token", filepath.Join(projected, "token")))
	directory, err := os.Open(projected)
	require.NoError(t, err)
	defer directory.Close()
	require.NoError(t, walker.walk(directory, "/", 0, sha256.New()))
	require.NoError(t, unix.Mkfifo(filepath.Join(projected, "unsafe"), 0600))
	require.ErrorContains(t, walker.walk(directory, "/", 0, sha256.New()), "socket/device/special")
	walker.entries = 262144
	require.Error(t, walker.walk(directory, "/", 0, sha256.New()))
}
func TestContainerdSocketRequiresExplicitRealSocket(t *testing.T) {
	for _, socket := range []string{"relative", "unix:///run/containerd/containerd.sock", "/tmp/../socket", "/proc/self/status"} {
		source, err := newContainerdImageSource(socket)
		require.Error(t, err, fmt.Sprint(socket))
		require.Nil(t, source)
	}
}

func TestLowerRedirectEvidenceRefusal(t *testing.T) {
	_, lower := indexFixture(t)
	indexFiles(t, lower)
	file, err := os.Open(lower)
	require.NoError(t, err)
	defer file.Close()
	walker := volumeWalker{ctx: context.Background(), rejectRedirect: true, allowSpecial: true}
	require.NoError(t, walker.walk(file, "/", 0, sha256.New()))
	require.NoError(t, unix.Setxattr(lower, "user.overlay.redirect", []byte("/elsewhere"), 0))
	require.ErrorContains(t, walker.walk(file, "/", 0, sha256.New()), "redirected")
}
func TestContainerSideSymlinkRootResolution(t *testing.T) {
	root, _ := indexFixture(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "run", "secrets"), 0700))
	require.NoError(t, os.Mkdir(filepath.Join(root, "var"), 0700))
	require.NoError(t, os.Symlink("/run", filepath.Join(root, "var", "run")))
	require.NoError(t, os.WriteFile(filepath.Join(root, "run", "secrets", "token"), []byte("data"), 0600))
	file, err := os.Open(root)
	require.NoError(t, err)
	defer file.Close()
	fd, err := unix.Openat2(int(file.Fd()), "/var/run/secrets/token", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
	require.NoError(t, err)
	require.NoError(t, unix.Close(fd))
	require.NoError(t, os.Symlink("/proc/self/fd/0", filepath.Join(root, "escape")))
	fd, err = unix.Openat2(int(file.Fd()), "/escape", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
	require.Error(t, err)
	require.Equal(t, -1, fd)
}

func TestStandardSHMAndOverlayUUID(t *testing.T) {
	e := goodImageEvidence()
	e.Spec.Mounts = []specs.Mount{{Type: "tmpfs", Source: "shm", Destination: "/dev/shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}}}
	require.NoError(t, validateImageSpec(e.Spec))
	e.Spec.Mounts[0].Destination = "/run"
	require.Error(t, validateImageSpec(e.Spec))
	e.Spec.Mounts[0].Destination = "/dev/shm"
	e.Spec.Mounts[0].Source = "/host/shm"
	require.Error(t, validateImageSpec(e.Spec))
	options := append(goodImageEvidence().Mounts[0].Options, "uuid=on")
	_, err := parseOverlayEvidence(options)
	require.NoError(t, err)
	options[len(options)-1] = "uuid=anything"
	_, err = parseOverlayEvidence(options)
	require.Error(t, err)
}
func TestAuthenticatedSandboxGeneratedFiles(t *testing.T) {
	id, sandbox := strings.Repeat("a", 64), strings.Repeat("b", 64)
	raw := []byte(fmt.Sprintf(`{"Version":"v1","Metadata":{"ID":%q,"SandboxID":%q}}`, id, sandbox))
	actual, err := criContainerSandbox(raw, id)
	require.NoError(t, err)
	require.Equal(t, sandbox, actual)
	_, err = criContainerSandbox(raw, sandbox)
	require.Error(t, err)
	pod := []byte(fmt.Sprintf(`{"Version":"v1","Metadata":{"ID":%q,"Config":{"Metadata":{"UID":"pod-uid","Namespace":"tenant"}}}}`, sandbox))
	uid, namespace, err := criSandboxIdentity(pod, sandbox)
	require.NoError(t, err)
	require.Equal(t, "pod-uid", uid)
	require.Equal(t, "tenant", namespace)
	_, _, err = criSandboxIdentity(pod, id)
	require.Error(t, err)
	e := goodImageEvidence()
	e.SandboxID = sandbox
	e.PodUID = uid
	e.PodNamespace = namespace
	e.Spec.Annotations = map[string]string{"io.kubernetes.cri.sandbox-id": sandbox, "io.kubernetes.cri.container-type": "container"}
	lower := []lowerLayer{{name: "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/123/fs"}}
	for _, name := range []string{"hosts", "hostname", "resolv.conf"} {
		m := specs.Mount{Type: "bind", Source: "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/" + sandbox + "/" + name, Destination: "/etc/" + name}
		require.True(t, validatedSandboxFile(e, m, lower))
		m.Source = strings.Replace(m.Source, sandbox, id, 1)
		require.False(t, validatedSandboxFile(e, m, lower))
	}
	m := specs.Mount{Source: "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db", Destination: "/etc/hosts"}
	require.False(t, validatedSandboxFile(e, m, lower))
	m = specs.Mount{Source: "/run/containerd/containerd.sock", Destination: "/etc/hosts"}
	require.False(t, validatedSandboxFile(e, m, lower))
	_, err = validateContainerdEvidence(e, id, 42)
	require.NoError(t, err)
	e.Spec.Annotations["io.kubernetes.cri.sandbox-id"] = id
	_, err = validateContainerdEvidence(e, id, 42)
	require.Error(t, err)
	process := &linuxLease{identity: sandboxpolicy.Binding{Namespace: "other"}}
	require.Error(t, validateEvidencePodIdentity(e, process))
}

func canonicalRootSeccomp() *specs.LinuxSeccomp {
	errno := uint(unix.EPERM)
	return &specs.LinuxSeccomp{DefaultAction: specs.ActAllow, Architectures: []specs.Arch{specs.ArchX86_64}, Syscalls: []specs.LinuxSyscall{
		{Names: []string{"chroot", "pivot_root", "unshare", "setns", "clone3"}, Action: specs.ActErrno, ErrnoRet: &errno},
		{Names: []string{"clone"}, Action: specs.ActErrno, ErrnoRet: &errno, Args: []specs.LinuxSeccompArg{{Index: 0, Value: uint64(unix.CLONE_NEWUSER), ValueTwo: uint64(unix.CLONE_NEWUSER), Op: specs.OpMaskedEqual}}},
		{Names: []string{"clone"}, Action: specs.ActErrno, ErrnoRet: &errno, Args: []specs.LinuxSeccompArg{{Index: 0, Value: uint64(unix.CLONE_NEWNS), ValueTwo: uint64(unix.CLONE_NEWNS), Op: specs.OpMaskedEqual}}},
	}}
}
func TestRootChangesRequireSynchronousSeccompBarrier(t *testing.T) {
	e := goodImageEvidence()
	require.NoError(t, validateImageSpec(e.Spec))
	e.Spec.Process.Capabilities.Bounding = append(e.Spec.Process.Capabilities.Bounding, "CAP_SYS_CHROOT")
	require.ErrorContains(t, validateImageSpec(e.Spec), "CAP_SYS_CHROOT")
	for _, mutate := range []func(*specs.LinuxSeccomp){
		func(p *specs.LinuxSeccomp) { p.DefaultAction = specs.ActErrno }, func(p *specs.LinuxSeccomp) { p.Architectures = nil }, func(p *specs.LinuxSeccomp) { p.Architectures = append(p.Architectures, specs.ArchX86) },
		func(p *specs.LinuxSeccomp) {
			p.Syscalls[0].Args = []specs.LinuxSeccompArg{{Index: 0, Value: 0, Op: specs.OpEqualTo}}
		}, func(p *specs.LinuxSeccomp) { p.Syscalls[0].Action = specs.ActAllow },
		func(p *specs.LinuxSeccomp) { p.Syscalls[0].Names = p.Syscalls[0].Names[1:] }, func(p *specs.LinuxSeccomp) { p.Syscalls[0].ErrnoRet = nil },
		func(p *specs.LinuxSeccomp) { p.Syscalls[1].Args[0].Index = 1 }, func(p *specs.LinuxSeccomp) { p.Syscalls[1].Args[0].ValueTwo = 0 }, func(p *specs.LinuxSeccomp) { p.Syscalls = p.Syscalls[:2] },
	} {
		profile := canonicalRootSeccomp()
		mutate(profile)
		require.Error(t, validateRootSeccomp(profile))
	}
	require.Error(t, validateRootSeccomp(nil))
}

func TestLiveRootBarrierStatus(t *testing.T) {
	good := []byte("Seccomp:\t2\nCapBnd:\t0\nCapEff:\t0\nCapPrm:\t0\nCapInh:\t0\nCapAmb:\t0\n")
	require.NoError(t, validateLiveRootBarrier(good))
	require.Error(t, validateLiveRootBarrier([]byte("Seccomp:\t0\n")))
	bad := strings.Replace(string(good), "CapBnd:\t0", fmt.Sprintf("CapBnd:\t%x", uint64(1)<<unix.CAP_SYS_CHROOT), 1)
	require.Error(t, validateLiveRootBarrier([]byte(bad)))
}

func sandboxShmEvidence() (containerdImageEvidence, specs.Mount) {
	e := goodImageEvidence()
	e.SandboxID = strings.Repeat("b", 64)
	e.PodUID = "pod-uid"
	e.PodNamespace = "test"
	m := specs.Mount{Type: "bind", Source: "/run/containerd/io.containerd.grpc.v1.cri/sandboxes/" + e.SandboxID + "/shm", Destination: "/dev/shm", Options: []string{"rbind"}}
	e.SandboxSpec = &specs.Spec{Linux: &specs.Linux{Namespaces: []specs.LinuxNamespace{{Type: specs.IPCNamespace}, {Type: specs.MountNamespace}}}, Mounts: []specs.Mount{{Type: "bind", Source: m.Source, Destination: "/dev/shm", Options: []string{"rbind", "ro", "nosuid", "nodev", "noexec"}}}}
	return e, m
}
func TestAuthenticatedSandboxShmMetadata(t *testing.T) {
	e, m := sandboxShmEvidence()
	require.True(t, validatedSandboxShm(e, m))
	// StateDir is authenticated by the sandbox spec, not guessed from RootDir.
	m.Source = "/custom-state/sandboxes/" + e.SandboxID + "/shm"
	e.SandboxSpec.Mounts[0].Source = m.Source
	require.True(t, validatedSandboxShm(e, m))
	for name, mutate := range map[string]func(*containerdImageEvidence, *specs.Mount){
		"wrong-sandbox":    func(e *containerdImageEvidence, m *specs.Mount) { e.SandboxID = strings.Repeat("c", 64) },
		"missing-metadata": func(e *containerdImageEvidence, m *specs.Mount) { e.PodUID = "" },
		"missing-spec":     func(e *containerdImageEvidence, m *specs.Mount) { e.SandboxSpec = nil },
		"missing-linux":    func(e *containerdImageEvidence, m *specs.Mount) { e.SandboxSpec.Linux = nil },
		"host-source": func(e *containerdImageEvidence, m *specs.Mount) {
			m.Source = "/dev/shm"
			e.SandboxSpec.Mounts[0].Source = m.Source
		},
		"wrong-source":        func(e *containerdImageEvidence, m *specs.Mount) { e.SandboxSpec.Mounts[0].Source = "/elsewhere" },
		"wrong-destination":   func(e *containerdImageEvidence, m *specs.Mount) { m.Destination = "/etc/hosts" },
		"not-bind":            func(e *containerdImageEvidence, m *specs.Mount) { m.Type = "tmpfs" },
		"missing-bind-option": func(e *containerdImageEvidence, m *specs.Mount) { m.Options = nil },
		"unknown-options":     func(e *containerdImageEvidence, m *specs.Mount) { m.Options = append(m.Options, "remount") },
		"writable-sandbox": func(e *containerdImageEvidence, m *specs.Mount) {
			e.SandboxSpec.Mounts[0].Options = []string{"rbind", "rw", "nosuid", "nodev", "noexec"}
		},
		"exec-sandbox": func(e *containerdImageEvidence, m *specs.Mount) {
			e.SandboxSpec.Mounts[0].Options = []string{"rbind", "ro", "nosuid", "nodev"}
		},
		"missing-nosuid": func(e *containerdImageEvidence, m *specs.Mount) {
			e.SandboxSpec.Mounts[0].Options = []string{"rbind", "ro", "nodev", "noexec"}
		},
		"missing-nodev": func(e *containerdImageEvidence, m *specs.Mount) {
			e.SandboxSpec.Mounts[0].Options = []string{"rbind", "ro", "nosuid", "noexec"}
		},
		"duplicate-mount": func(e *containerdImageEvidence, m *specs.Mount) {
			e.SandboxSpec.Mounts = append(e.SandboxSpec.Mounts, e.SandboxSpec.Mounts[0])
		},
		"mount-budget": func(e *containerdImageEvidence, m *specs.Mount) { e.SandboxSpec.Mounts = make([]specs.Mount, 129) },
		"host-ipc": func(e *containerdImageEvidence, m *specs.Mount) {
			e.SandboxSpec.Linux.Namespaces[0].Path = "/proc/1/ns/ipc"
		},
		"host-mount": func(e *containerdImageEvidence, m *specs.Mount) {
			e.SandboxSpec.Linux.Namespaces[1].Path = "/proc/1/ns/mnt"
		},
		"missing-ipc": func(e *containerdImageEvidence, m *specs.Mount) {
			e.SandboxSpec.Linux.Namespaces = e.SandboxSpec.Linux.Namespaces[1:]
		},
		"duplicate-ipc": func(e *containerdImageEvidence, m *specs.Mount) {
			e.SandboxSpec.Linux.Namespaces = append(e.SandboxSpec.Linux.Namespaces, e.SandboxSpec.Linux.Namespaces[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			e, m := sandboxShmEvidence()
			mutate(&e, &m)
			require.False(t, validatedSandboxShm(e, m))
		})
	}
}
func TestSandboxShmRequiresActualRestrictedTmpfsRoot(t *testing.T) {
	const entry = "123 1 0:42 / /run/containerd/sandboxes/id/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k\n"
	good := unix.Statfs_t{Type: unix.TMPFS_MAGIC, Flags: unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC}
	require.NoError(t, validateSandboxShmFacts(good, unix.S_IFDIR|01777, []byte(entry), 123))
	for name, tc := range map[string]struct {
		fs   unix.Statfs_t
		mode uint32
		info string
		id   uint64
	}{
		"ordinary-filesystem": {unix.Statfs_t{Type: unix.EXT4_SUPER_MAGIC, Flags: good.Flags}, unix.S_IFDIR, entry, 123},
		"regular-file":        {good, unix.S_IFREG, entry, 123},
		"missing-fs-flags":    {unix.Statfs_t{Type: unix.TMPFS_MAGIC}, unix.S_IFDIR, entry, 123},
		"subtree":             {good, unix.S_IFDIR, strings.Replace(entry, "0:42 / ", "0:42 /subtree ", 1), 123},
		"exec-mount":          {good, unix.S_IFDIR, strings.Replace(entry, ",noexec", "", 1), 123},
		"suid-mount":          {good, unix.S_IFDIR, strings.Replace(entry, ",nosuid", "", 1), 123},
		"device-mount":        {good, unix.S_IFDIR, strings.Replace(entry, ",nodev", "", 1), 123},
		"wrong-fstype":        {good, unix.S_IFDIR, strings.Replace(entry, "- tmpfs", "- ext4", 1), 123},
		"missing-id":          {good, unix.S_IFDIR, entry, 124},
		"duplicate-id":        {good, unix.S_IFDIR, entry + entry, 123},
		"malformed":           {good, unix.S_IFDIR, "123 1\n", 123},
		"missing-separator":   {good, unix.S_IFDIR, strings.Replace(entry, "- tmpfs", "tmpfs", 1), 123},
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, validateSandboxShmFacts(tc.fs, tc.mode, []byte(tc.info), tc.id)) })
	}
}
func TestSandboxShmPinsRejectOrdinaryFiles(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "not-shm")
	require.NoError(t, err)
	defer f.Close()
	require.Error(t, validateSandboxShmPins(f, f, nil, nil, containerdImageEvidence{}, nil))
}
func TestSandboxShmSpecParticipatesInEvidenceHash(t *testing.T) {
	e, _ := sandboxShmEvidence()
	before, err := evidenceHash(e)
	require.NoError(t, err)
	e.SandboxSpec.Mounts[0].Source = "/changed"
	after, err := evidenceHash(e)
	require.NoError(t, err)
	require.NotEqual(t, before, after)
}

func TestRuntimeCgroupMountRequiresCanonicalReadOnlySpec(t *testing.T) {
	good := specs.Mount{Type: "cgroup", Source: "cgroup", Destination: "/sys/fs/cgroup", Options: []string{"nosuid", "noexec", "nodev", "relatime", "ro"}}
	require.True(t, validCgroupMount(good))
	e := goodImageEvidence()
	e.Spec.Mounts = []specs.Mount{good}
	require.NoError(t, validateImageSpec(e.Spec))
	for name, mutate := range map[string]func(*specs.Mount){
		"writable":    func(m *specs.Mount) { m.Options = []string{"nosuid", "nodev", "noexec", "rw"} },
		"exec":        func(m *specs.Mount) { m.Options = []string{"nosuid", "nodev", "ro"} },
		"devices":     func(m *specs.Mount) { m.Options = []string{"nosuid", "noexec", "ro"} },
		"suid":        func(m *specs.Mount) { m.Options = []string{"nodev", "noexec", "ro"} },
		"source":      func(m *specs.Mount) { m.Source = "/sys/fs/cgroup" },
		"destination": func(m *specs.Mount) { m.Destination = "/sys" },
		"remount":     func(m *specs.Mount) { m.Options = append(m.Options, "remount") },
		"duplicate":   func(m *specs.Mount) { m.Options = []string{"nosuid", "nodev", "noexec", "ro", "ro"} },
	} {
		t.Run(name, func(t *testing.T) {
			m := good
			m.Options = append([]string(nil), good.Options...)
			mutate(&m)
			require.False(t, validCgroupMount(m))
			e := goodImageEvidence()
			e.Spec.Mounts = []specs.Mount{m}
			require.Error(t, validateImageSpec(e.Spec))
		})
	}
}
func TestRuntimeCgroupMountRequiresActualRestrictedCgroup2(t *testing.T) {
	const entry = "123 1 0:42 /kubepods/test /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n"
	good := unix.Statfs_t{Type: unix.CGROUP2_SUPER_MAGIC, Flags: unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC}
	require.NoError(t, validateCgroupMountFacts(good, unix.S_IFDIR, []byte(entry), 123))
	for name, tc := range map[string]struct {
		fs   unix.Statfs_t
		mode uint32
		info string
	}{
		"cgroup-v1":      {unix.Statfs_t{Type: unix.CGROUP_SUPER_MAGIC, Flags: good.Flags}, unix.S_IFDIR, entry},
		"writable-facts": {unix.Statfs_t{Type: good.Type, Flags: good.Flags &^ unix.ST_RDONLY}, unix.S_IFDIR, entry},
		"regular-file":   {good, unix.S_IFREG, entry},
		"writable-mount": {good, unix.S_IFDIR, strings.Replace(entry, "ro,nosuid", "rw,nosuid", 1)},
		"wrong-fstype":   {good, unix.S_IFDIR, strings.Replace(entry, "- cgroup2", "- cgroup", 1)},
		"missing-mount":  {good, unix.S_IFDIR, strings.Replace(entry, "123 1", "124 1", 1)},
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, validateCgroupMountFacts(tc.fs, tc.mode, []byte(tc.info), 123)) })
	}
}
func TestRuntimeCgroupMountRejectsOrdinaryDestination(t *testing.T) {
	root, err := os.Open(t.TempDir())
	require.NoError(t, err)
	defer root.Close()
	require.NoError(t, os.MkdirAll(filepath.Join(root.Name(), "sys/fs/cgroup"), 0700))
	spec := &specs.Spec{Mounts: []specs.Mount{{Type: "cgroup", Source: "cgroup", Destination: "/sys/fs/cgroup", Options: []string{"ro", "nosuid", "nodev", "noexec"}}}}
	require.Error(t, validateCgroupMounts(spec, root, nil))
}

func unprivilegedShmSpec() *specs.Spec {
	spec := goodImageEvidence().Spec
	spec.Process.NoNewPrivileges = true
	spec.Process.Capabilities = &specs.LinuxCapabilities{}
	spec.Linux.Resources = &specs.LinuxResources{Devices: []specs.LinuxDeviceCgroup{{Allow: false, Access: "rwm"}}}
	return spec
}

const unprivilegedShmStatus = "Seccomp:\t2\nNoNewPrivs:\t1\nCapBnd:\t0000000000000000\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapInh:\t0000000000000000\nCapAmb:\t0000000000000000\n"

func TestSandboxShmDestinationRequiresNarrowUnprivilegedMatrix(t *testing.T) {
	require.NoError(t, validateSandboxShmUnprivileged(unprivilegedShmSpec(), []byte(unprivilegedShmStatus)))
	spec := unprivilegedShmSpec()
	spec.Linux.Resources.Devices[0].Type = "a"
	require.NoError(t, validateSandboxShmUnprivileged(spec, []byte(unprivilegedShmStatus)))
	pointer := func(v int64) *int64 { return &v }
	for name, mutate := range map[string]func(*specs.Spec){
		"no-new-privileges-false": func(s *specs.Spec) { s.Process.NoNewPrivileges = false },
		"capabilities-missing":    func(s *specs.Spec) { s.Process.Capabilities = nil },
		"bounding-cap":            func(s *specs.Spec) { s.Process.Capabilities.Bounding = []string{"CAP_CHOWN"} },
		"effective-cap":           func(s *specs.Spec) { s.Process.Capabilities.Effective = []string{"CAP_CHOWN"} },
		"permitted-cap":           func(s *specs.Spec) { s.Process.Capabilities.Permitted = []string{"CAP_CHOWN"} },
		"inheritable-cap":         func(s *specs.Spec) { s.Process.Capabilities.Inheritable = []string{"CAP_CHOWN"} },
		"ambient-cap":             func(s *specs.Spec) { s.Process.Capabilities.Ambient = []string{"CAP_CHOWN"} },
		"resources-missing":       func(s *specs.Spec) { s.Linux.Resources = nil },
		"devices-missing":         func(s *specs.Spec) { s.Linux.Resources.Devices = nil },
		"baseline-allow":          func(s *specs.Spec) { s.Linux.Resources.Devices[0].Allow = true },
		"typed-char-baseline":     func(s *specs.Spec) { s.Linux.Resources.Devices[0].Type = "c" },
		"typed-block-baseline":    func(s *specs.Spec) { s.Linux.Resources.Devices[0].Type = "b" },
		"major-zero-pointer":      func(s *specs.Spec) { s.Linux.Resources.Devices[0].Major = pointer(0) },
		"minor-pointer":           func(s *specs.Spec) { s.Linux.Resources.Devices[0].Minor = pointer(1) },
		"narrow-access":           func(s *specs.Spec) { s.Linux.Resources.Devices[0].Access = "rw" },
		"reordered-access":        func(s *specs.Spec) { s.Linux.Resources.Devices[0].Access = "mrw" },
		"appended-allow": func(s *specs.Spec) {
			s.Linux.Resources.Devices = append(s.Linux.Resources.Devices, specs.LinuxDeviceCgroup{Allow: true, Type: "c", Access: "rwm"})
		},
		"appended-deny": func(s *specs.Spec) {
			s.Linux.Resources.Devices = append(s.Linux.Resources.Devices, specs.LinuxDeviceCgroup{Allow: false, Access: "rwm"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := unprivilegedShmSpec()
			mutate(spec)
			require.Error(t, validateSandboxShmUnprivileged(spec, []byte(unprivilegedShmStatus)))
		})
	}
}
func TestSandboxShmDestinationRequiresLiveUnprivilegedFacts(t *testing.T) {
	for _, field := range []string{"CapBnd:", "CapEff:", "CapPrm:", "CapInh:", "CapAmb:"} {
		t.Run(field, func(t *testing.T) {
			status := strings.Replace(unprivilegedShmStatus, field+"\t0000000000000000", field+"\t0000000000000001", 1)
			require.Error(t, validateSandboxShmUnprivileged(unprivilegedShmSpec(), []byte(status)))
		})
	}
	for name, status := range map[string]string{
		"nnp-zero":      strings.Replace(unprivilegedShmStatus, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1),
		"nnp-missing":   strings.Replace(unprivilegedShmStatus, "NoNewPrivs:\t1\n", "", 1),
		"nnp-duplicate": unprivilegedShmStatus + "NoNewPrivs:\t1\n",
		"seccomp-zero":  strings.Replace(unprivilegedShmStatus, "Seccomp:\t2", "Seccomp:\t0", 1),
		"cap-missing":   strings.Replace(unprivilegedShmStatus, "CapBnd:\t0000000000000000\n", "", 1),
		"cap-duplicate": unprivilegedShmStatus + "CapBnd:\t0\n",
		"cap-malformed": strings.Replace(unprivilegedShmStatus, "CapBnd:\t0000000000000000", "CapBnd:\tgarbage", 1),
		"cap-overflow":  strings.Replace(unprivilegedShmStatus, "CapBnd:\t0000000000000000", "CapBnd:\t10000000000000000", 1),
		"oversized":     strings.Repeat("x", 65537),
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateSandboxShmUnprivileged(unprivilegedShmSpec(), []byte(status)))
		})
	}
}
func TestSandboxShmDestinationWaivesOnlyMountFlags(t *testing.T) {
	const mounts = "123 1 0:42 / /dev/shm rw,relatime - tmpfs shm rw,size=65536k\n"
	fs := unix.Statfs_t{Type: unix.TMPFS_MAGIC}
	require.Error(t, validateSandboxShmFacts(fs, unix.S_IFDIR, []byte(mounts), 123), "source must always retain restrictive flags")
	require.NoError(t, validateSandboxShmDestinationFacts(fs, unix.S_IFDIR, []byte(mounts), 123, unprivilegedShmSpec(), []byte(unprivilegedShmStatus)))
	require.Error(t, validateSandboxShmDestinationFacts(fs, unix.S_IFDIR, []byte(mounts), 123, goodImageEvidence().Spec, []byte(unprivilegedShmStatus)))
	for name, tc := range map[string]struct {
		fs     unix.Statfs_t
		mode   uint32
		mounts string
		id     uint64
	}{
		"not-tmpfs":          {unix.Statfs_t{Type: unix.EXT4_SUPER_MAGIC}, unix.S_IFDIR, mounts, 123},
		"not-dir":            {fs, unix.S_IFREG, mounts, 123},
		"subtree":            {fs, unix.S_IFDIR, strings.Replace(mounts, "0:42 / ", "0:42 /subtree ", 1), 123},
		"wrong-mount":        {fs, unix.S_IFDIR, mounts, 124},
		"wrong-mount-fstype": {fs, unix.S_IFDIR, strings.Replace(mounts, "- tmpfs", "- ext4", 1), 123},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateSandboxShmDestinationFacts(tc.fs, tc.mode, []byte(tc.mounts), tc.id, unprivilegedShmSpec(), []byte(unprivilegedShmStatus)))
		})
	}
}

// Callback source lets tests observe retries without recreating the image lease.
type callbackImageEvidenceSource func(context.Context, string) (containerdImageEvidence, error)

func (f callbackImageEvidenceSource) Evidence(ctx context.Context, id string) (containerdImageEvidence, error) {
	return f(ctx, id)
}

func TestImageEvidenceTransientRetrievalRetriesSameLease(t *testing.T) {
	for name, fault := range map[string]error{
		"grpc unavailable":         status.Error(codes.Unavailable, "runtime restarting"),
		"wrapped grpc unavailable": fmt.Errorf("runtime lookup: %w", status.Error(codes.Unavailable, "runtime restarting")),
		"containerd unavailable":   fmt.Errorf("runtime lookup: %w", errdefs.ErrUnavailable),
		"connection refused":       &net.OpError{Op: "dial", Net: "unix", Err: unix.ECONNREFUSED},
		"connection reset":         &net.OpError{Op: "read", Net: "unix", Err: unix.ECONNRESET},
		"broken pipe":              &net.OpError{Op: "write", Net: "unix", Err: unix.EPIPE},
		"connection eof":           &net.OpError{Op: "read", Net: "unix", Err: io.EOF},
	} {
		t.Run(name, func(t *testing.T) {
			evidence := goodImageEvidence()
			process := &linuxLease{identity: sandboxpolicy.Binding{Runtime: "containerd", ContainerID: evidence.ID, PID: evidence.PID}}
			identity := process.identity
			calls := 0
			lease := &trustedImageLease{Complete: true, process: process}
			lease.source = callbackImageEvidenceSource(func(ctx context.Context, id string) (containerdImageEvidence, error) {
				require.Equal(t, evidence.ID, id)
				calls++
				if calls == 1 {
					return containerdImageEvidence{}, fault
				}
				return evidence, nil
			})
			require.ErrorIs(t, lease.CheckContext(context.Background()), fault)
			require.True(t, lease.Complete)
			require.Nil(t, lease.failure)
			require.Equal(t, 1, calls)
			require.Same(t, process, lease.process)
			require.Equal(t, identity, process.identity)
			// This unprivileged fixture has no pinned overlay root. Returning
			// real valid evidence proves the next call reaches re-attestation:
			// its deliberately missing baseline hash must now fail closed.
			err := lease.CheckContext(context.Background())
			require.EqualError(t, err, "runtime image evidence changed")
			require.Equal(t, 2, calls)
			require.False(t, lease.Complete)
			require.ErrorIs(t, lease.failure, err)
			require.ErrorIs(t, lease.CheckContext(context.Background()), err)
			require.Equal(t, 2, calls, "confirmed evidence mismatch must remain sticky")
		})
	}
}

func TestImageEvidenceSemanticSourceFailuresRemainSticky(t *testing.T) {
	for name, fault := range map[string]error{
		"metadata mismatch":         errors.New("CRI container/sandbox metadata mismatch"),
		"unsupported runtime":       errors.New("only containerd overlayfs snapshotter is supported"),
		"capacity":                  errors.New("snapshot ancestry budget exceeded"),
		"malformed data eof":        io.EOF,
		"bare io failure":           unix.EIO,
		"not found":                 errdefs.ErrNotFound,
		"resource exhausted":        status.Error(codes.ResourceExhausted, "budget exceeded"),
		"invalid argument":          status.Error(codes.InvalidArgument, "invalid metadata"),
		"failed precondition":       status.Error(codes.FailedPrecondition, "invalid runtime"),
		"network permission denied": &net.OpError{Op: "dial", Net: "unix", Err: unix.EACCES},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			lease := &trustedImageLease{Complete: true, process: &linuxLease{}}
			lease.source = callbackImageEvidenceSource(func(context.Context, string) (containerdImageEvidence, error) {
				calls++
				return containerdImageEvidence{}, fault
			})
			require.ErrorIs(t, lease.CheckContext(context.Background()), fault)
			require.False(t, lease.Complete)
			require.ErrorIs(t, lease.failure, fault)
			require.ErrorIs(t, lease.CheckContext(context.Background()), fault)
			require.Equal(t, 1, calls)
		})
	}
}
