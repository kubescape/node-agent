package igbackend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"golang.org/x/sys/unix"
)

// ContainerdFullSource owns one trusted containerd connection. Close must follow
// all native owners' confirmed detach and lease release; it refuses outstanding
// preparations/leases. A failed Close seals admission, and can be retried.
//
// The administrator must provide a protected host root, host proc/cgroup mounts
// and containerd socket/parent directory from the same host. These privileged
// inputs are not authenticated by policy metadata or by merely naming a path.
// The host-proc check additionally requires Linux's initial PID namespace and
// pins PID1's current mount namespace; unsupported/container-local proc fails.
type ContainerdFullSource struct {
	mu              sync.Mutex
	source          imageEvidenceSource
	closeSource     func() error
	hostRoot        string
	validator       LinuxValidator
	limits          ImageIndexLimits
	outstanding     uint64
	closing, closed bool
}

func NewContainerdFullSource(socket, hostRoot, procRoot, cgroupRoot string, limits ImageIndexLimits) (*ContainerdFullSource, error) {
	for _, p := range []string{hostRoot, procRoot, cgroupRoot} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, fmt.Errorf("canonical administrator host paths required")
		}
	}
	normalized, err := normalizeIndexLimits(limits)
	if err != nil {
		return nil, err
	}
	source, err := newContainerdImageSource(socket)
	if err != nil {
		return nil, err
	}
	return &ContainerdFullSource{source: source, closeSource: source.Close, hostRoot: hostRoot, validator: LinuxValidator{ProcRoot: procRoot, CgroupRoot: cgroupRoot}, limits: normalized}, nil
}

func (s *ContainerdFullSource) Prepare(ctx context.Context, binding sandboxpolicy.Binding) (FullBindingLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closing || s.closed || s.source == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("containerd full source is closed")
	}
	if s.outstanding >= FullBackendMaxBindings {
		s.mu.Unlock()
		return nil, fmt.Errorf("full binding source capacity exceeded")
	}
	s.outstanding++
	s.mu.Unlock()
	lease := &containerdFullLease{owner: s}
	fail := func(err error) (FullBindingLease, error) {
		if cleanup := lease.Close(); cleanup != nil {
			return lease, errors.Join(err, cleanup)
		}
		return nil, err
	}
	var err error
	lease.host, err = pinHostNamespaces(s.validator.ProcRoot)
	if err != nil {
		return fail(err)
	}
	process, err := s.validator.Acquire(ctx, binding)
	if err != nil {
		return fail(err)
	}
	// This concrete validator is local and always returns *linuxLease.
	lease.process = process.(*linuxLease)
	lease.image, err = acquireImageEvidence(ctx, s.source, lease.process, s.hostRoot, s.limits)
	if err != nil {
		return fail(err)
	}
	lease.origins, err = snapshotImageOrigins(lease.image)
	if err != nil {
		return fail(err)
	}
	if err = lease.Check(ctx); err != nil {
		return fail(err)
	}
	return lease, nil
}
func (s *ContainerdFullSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closing = true
	if s.outstanding != 0 {
		return fmt.Errorf("containerd full source still owns %d binding leases/preparations", s.outstanding)
	}
	if s.closeSource != nil {
		if err := s.closeSource(); err != nil {
			return err
		}
	}
	s.closed = true
	return nil
}

type containerdFullLease struct {
	mu              sync.Mutex
	owner           *ContainerdFullSource
	process         *linuxLease
	image           *trustedImageLease
	host            *hostNamespacePins
	origins         *execruntime.ImageOriginSnapshot
	closing, closed bool
}

func snapshotImageOrigins(image *trustedImageLease) (*execruntime.ImageOriginSnapshot, error) {
	image.mu.Lock()
	defer image.mu.Unlock()
	if image.closed || image.failure != nil || !image.Complete || len(image.Inodes) > execruntime.MaxImageOrigins {
		return nil, fmt.Errorf("complete bounded image evidence required")
	}
	snapshot := &execruntime.ImageOriginSnapshot{Complete: true, Keys: make([]execruntime.ImageOriginKey, len(image.Inodes))}
	for i, key := range image.Inodes {
		snapshot.Keys[i] = execruntime.ImageOriginKey{Inode: key.Inode, Major: key.Major, Minor: key.Minor}
	}
	if err := execruntime.ValidateImageOriginSnapshot(snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}
func (l *containerdFullLease) Check(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing || l.closed || l.process == nil || l.image == nil || l.host == nil {
		return fmt.Errorf("full binding lease unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.host.check(); err != nil {
		return err
	}
	if err := l.image.CheckContext(ctx); err != nil {
		return err
	}
	// A same-host mount namespace is never made safe by policy exemptions.
	host, err := namespaceIdentity(l.host.mount, unix.CLONE_NEWNS)
	if err != nil {
		return err
	}
	workload, err := namespaceIdentity(l.process.namespace, unix.CLONE_NEWNS)
	if err != nil {
		return err
	}
	if host == workload {
		return fmt.Errorf("host mount namespace cannot be bound")
	}
	return nil
}

// SharedContainerName returns the immutable name retained from the validated
// runtime/Kubernetes binding. The caller must first successfully Check the lease;
// this getter is not attestation and makes no runtime or filesystem observations.
// Its built-in signature permits the shared IG consumer to select this optional
// contract without changing the provider's dependency pin.
func (l *containerdFullLease) SharedContainerName() (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing || l.closed || l.process == nil || l.image == nil || l.host == nil {
		return "", fmt.Errorf("full binding lease unavailable")
	}
	name := l.process.identity.ContainerName
	// Match the shared compiler's 255-byte string domain, not a caller override
	// or a separately decoded, potentially inconsistent CRI metadata name.
	if name == "" || len(name) > 255 || !utf8.ValidString(name) || strings.IndexByte(name, 0) >= 0 {
		return "", fmt.Errorf("bounded valid shared container name required")
	}
	return name, nil
}

func (l *containerdFullLease) InitProc() *os.File {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.process == nil {
		return nil
	}
	return l.process.proc
}
func (l *containerdFullLease) Cgroup() *os.File {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.process == nil {
		return nil
	}
	return l.process.cgroup
}
func (l *containerdFullLease) MountNamespace() *os.File {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.process == nil {
		return nil
	}
	return l.process.namespace
}
func (l *containerdFullLease) HostMountNamespace() *os.File {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.host == nil {
		return nil
	}
	return l.host.mount
}
func (l *containerdFullLease) ImageOrigins() *execruntime.ImageOriginSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing || l.closed || l.origins == nil {
		return nil
	}
	out := *l.origins
	out.Keys = append([]execruntime.ImageOriginKey(nil), out.Keys...)
	return &out
}

// Close consumes the lease even when an OS close reports an error. The native
// owner drops its reference after ReleaseAfterDetach, so every owned handle and
// the shared-source reservation must be released in this call, not on a retry.
func (l *containerdFullLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closing = true
	var errs []error
	// Evidence owns borrowed process references, so release it before proc pins.
	if l.image != nil {
		errs = append(errs, l.image.Close())
		l.image = nil
	}
	if l.process != nil {
		errs = append(errs, l.process.Close())
		l.process = nil
	}
	if l.host != nil {
		errs = append(errs, l.host.close())
		l.host = nil
	}
	l.origins = nil
	l.closed = true
	if l.owner != nil {
		l.owner.mu.Lock()
		l.owner.outstanding--
		l.owner.mu.Unlock()
		l.owner = nil
	}
	return errors.Join(errs...)
}

// Linux UAPI include/uapi/linux/nsfs.h: enum init_ns_ino. Unlike NS_GET_PARENT
// returning EPERM (also permission failure), this identifies the initial PID
// namespace, not merely a namespace whose parent the caller cannot inspect.
const initialPIDNamespaceInode = uint64(0xEFFFFFFC)

type hostNamespacePins struct{ proc, pid, mount *os.File }

func pinHostNamespaces(procRoot string) (*hostNamespacePins, error) {
	if !filepath.IsAbs(procRoot) || filepath.Clean(procRoot) != procRoot {
		return nil, fmt.Errorf("canonical host proc required")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Join(procRoot, "1"), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, err
	}
	pins := &hostNamespacePins{proc: os.NewFile(uintptr(fd), "host init proc")}
	fail := func(err error) (*hostNamespacePins, error) { return nil, errors.Join(err, pins.close()) }
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil {
		return fail(err)
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return fail(fmt.Errorf("host proc is not procfs"))
	}
	pins.pid, err = openNamespace(pins.proc, "pid")
	if err != nil {
		return fail(err)
	}
	pins.mount, err = openNamespace(pins.proc, "mnt")
	if err != nil {
		return fail(err)
	}
	if err = pins.check(); err != nil {
		return fail(err)
	}
	return pins, nil
}
func openNamespace(proc *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(proc.Fd()), "ns/"+name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name+" namespace"), nil
}
func namespaceIdentity(file *os.File, kind int) ([2]uint64, error) {
	if file == nil {
		return [2]uint64{}, fmt.Errorf("namespace pin required")
	}
	fd := int(file.Fd())
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return [2]uint64{}, err
	}
	if fs.Type != unix.NSFS_MAGIC {
		return [2]uint64{}, fmt.Errorf("namespace is not NSFS")
	}
	actual, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil {
		return [2]uint64{}, err
	}
	if actual != kind {
		return [2]uint64{}, fmt.Errorf("unexpected namespace type")
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return [2]uint64{}, err
	}
	return [2]uint64{uint64(stat.Dev), stat.Ino}, nil
}
func (h *hostNamespacePins) check() error {
	pid, err := namespaceIdentity(h.pid, unix.CLONE_NEWPID)
	if err != nil {
		return err
	}
	if pid[1] != initialPIDNamespaceInode {
		return fmt.Errorf("host proc is not in the initial PID namespace")
	}
	if _, err = namespaceIdentity(h.mount, unix.CLONE_NEWNS); err != nil {
		return err
	}
	fd, err := unix.Openat(int(h.proc.Fd()), "status", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	status := os.NewFile(uintptr(fd), "host init status")
	data, e := io.ReadAll(io.LimitReader(status, 64*1024+1))
	ce := status.Close()
	if e != nil || ce != nil {
		return errors.Join(e, ce)
	}
	if err = validateHostInitStatus(data); err != nil {
		return err
	}
	for _, item := range []struct {
		name string
		file *os.File
		kind int
	}{{"pid", h.pid, unix.CLONE_NEWPID}, {"mnt", h.mount, unix.CLONE_NEWNS}} {
		current, err := openNamespace(h.proc, item.name)
		if err != nil {
			return err
		}
		actual, e := namespaceIdentity(current, item.kind)
		ce := current.Close()
		if e != nil || ce != nil {
			return errors.Join(e, ce)
		}
		pinned, e := namespaceIdentity(item.file, item.kind)
		if e != nil {
			return e
		}
		if actual != pinned {
			return fmt.Errorf("host init namespace changed")
		}
	}
	return nil
}
func validateHostInitStatus(data []byte) error {
	if len(data) > 64*1024 {
		return fmt.Errorf("oversized host init status")
	}
	required := map[string]bool{"Pid": false, "Tgid": false, "NSpid": false, "NStgid": false}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		seen, needed := required[key]
		if !needed {
			continue
		}
		if seen || strings.TrimSpace(value) != "1" {
			return fmt.Errorf("host proc must identify initial PID1")
		}
		required[key] = true
	}
	for _, seen := range required {
		if !seen {
			return fmt.Errorf("incomplete host init status")
		}
	}
	return nil
}
func (h *hostNamespacePins) close() error {
	var errs []error
	for _, slot := range []**os.File{&h.mount, &h.pid, &h.proc} {
		if *slot != nil {
			errs = append(errs, (*slot).Close())
			*slot = nil
		}
	}
	return errors.Join(errs...)
}
