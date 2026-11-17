package igbackend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"golang.org/x/sys/unix"
)

// LinuxValidator uses host-visible procfs and the unified cgroup mount. Runtime
// and container ID must originate from the authoritative runtime cache; neither
// is inferred from cgroup names. Nonempty roots support node-agent host mounts.
//
// Binding cgroup paths are host-absolute (IG reads them in PID 1's cgroup
// namespace and CgroupRoot is the host cgroup2 mount), but the kernel renders
// /proc/<pid>/cgroup relative to the reader's cgroup namespace. A pod-confined
// agent (containerd on cgroup v2 gives every non-host container a private
// cgroupns) would read "0::/../<path>", so membership is re-read only from
// the pinned initial cgroup namespace of ProcRoot's PID 1.
type LinuxValidator struct{ ProcRoot, CgroupRoot string }
type linuxLease struct {
	proc, cgroup, namespace, hostCgroup *os.File
	identity                            sandboxpolicy.Binding
	start                               string
}

// Linux UAPI include/uapi/linux/nsfs.h: enum init_ns_ino PROC_CGROUP_INIT_INO.
const initialCgroupNamespaceInode = uint64(0xEFFFFFFB)

// restoreThreadCgroupNamespace is a test seam for the post-read restore setns.
var restoreThreadCgroupNamespace = func(fd int) error { return unix.Setns(fd, unix.CLONE_NEWCGROUP) }

// pinInitialCgroupNamespace pins PID 1's cgroup namespace from a procfs root and
// refuses anything but the kernel's initial cgroup namespace.
func pinInitialCgroupNamespace(procRoot string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Join(procRoot, "1"), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, err
	}
	init := os.NewFile(uintptr(fd), "host init proc")
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return nil, errors.Join(err, init.Close())
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, errors.Join(fmt.Errorf("host proc is not procfs"), init.Close())
	}
	ns, err := openNamespace(init, "cgroup")
	if closeErr := init.Close(); err != nil || closeErr != nil {
		if ns != nil {
			closeErr = errors.Join(closeErr, ns.Close())
		}
		return nil, errors.Join(err, closeErr)
	}
	if err := requireInitialCgroupNamespace(ns); err != nil {
		return nil, errors.Join(err, ns.Close())
	}
	return ns, nil
}
func requireInitialCgroupNamespace(ns *os.File) error {
	id, err := namespaceIdentity(ns, unix.CLONE_NEWCGROUP)
	if err != nil {
		return err
	}
	if id[1] != initialCgroupNamespaceInode {
		return fmt.Errorf("host cgroup namespace is not the initial cgroup namespace")
	}
	return nil
}

func (v LinuxValidator) Acquire(ctx context.Context, b sandboxpolicy.Binding) (Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if b.Runtime == "" || b.ContainerID == "" || b.PID == 0 || b.CgroupID == 0 || b.MountNamespace == 0 || !path.IsAbs(b.CgroupPath) || path.Clean(b.CgroupPath) != b.CgroupPath || b.CgroupPath == "/" {
		return nil, fmt.Errorf("complete non-root live container identity required")
	}
	procRoot, cgRoot := v.ProcRoot, v.CgroupRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	if cgRoot == "" {
		cgRoot = "/sys/fs/cgroup"
	}
	proc, err := os.Open(filepath.Join(procRoot, strconv.FormatUint(uint64(b.PID), 10)))
	if err != nil {
		return nil, err
	}
	lease := &linuxLease{proc: proc, identity: b}
	fail := func(err error) (Lease, error) { return nil, errors.Join(err, lease.Close()) }
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(proc.Fd()), &fs); err != nil {
		return fail(err)
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return fail(fmt.Errorf("process root is not procfs"))
	}
	if lease.hostCgroup, err = pinInitialCgroupNamespace(procRoot); err != nil {
		return fail(err)
	}
	root, err := os.Open(cgRoot)
	if err != nil {
		return fail(err)
	}
	fd, err := unix.Openat2(int(root.Fd()), strings.TrimPrefix(b.CgroupPath, "/"), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
	closeErr := root.Close()
	if err != nil || closeErr != nil {
		if err == nil {
			return fail(errors.Join(closeErr, unix.Close(fd)))
		}
		return fail(errors.Join(err, closeErr))
	}
	lease.cgroup = os.NewFile(uintptr(fd), b.CgroupPath)
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return fail(err)
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return fail(fmt.Errorf("binding is not on cgroup v2"))
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fail(err)
	}
	if stat.Ino != b.CgroupID {
		return fail(fmt.Errorf("cgroup inode changed"))
	}
	ns, err := unix.Openat(int(proc.Fd()), "ns/mnt", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	lease.namespace = os.NewFile(uintptr(ns), "mount namespace")
	if err := unix.Fstat(ns, &stat); err != nil {
		return fail(err)
	}
	if stat.Ino != b.MountNamespace {
		return fail(fmt.Errorf("mount namespace changed"))
	}
	lease.start, err = lease.readStart()
	if err != nil {
		return fail(err)
	}
	if err := lease.Check(); err != nil {
		return fail(err)
	}
	return lease, nil
}
func (l *linuxLease) read(name string) (result []byte, retErr error) {
	fd, err := unix.Openat(int(l.proc.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { retErr = errors.Join(retErr, f.Close()) }()
	// proc entries are small; constrain unexpected/malformed input.
	b, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 64*1024 {
		return nil, fmt.Errorf("oversized proc entry")
	}
	return b, nil
}
func (l *linuxLease) readStart() (string, error) {
	data, err := l.read("stat")
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return "", fmt.Errorf("malformed process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	// Fields after comm begin at3; starttime is22.
	if len(fields) <= 19 {
		return "", fmt.Errorf("incomplete process stat")
	}
	return fields[19], nil
}
func (l *linuxLease) Check() (err error) {
	start, err := l.readStart()
	if err != nil {
		return err
	}
	if start != l.start {
		return fmt.Errorf("process identity changed")
	}
	data, err := l.readHostCgroup()
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::") {
			if found || strings.TrimPrefix(line, "0::") != l.identity.CgroupPath {
				return fmt.Errorf("process cgroup changed")
			}
			found = true
		}
	}
	if !found {
		return fmt.Errorf("missing unified process cgroup")
	}
	fd, err := unix.Openat(int(l.proc.Fd()), "ns/mnt", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Ino != l.identity.MountNamespace {
		return fmt.Errorf("process mount namespace changed")
	}
	return nil
}

// readHostCgroup reads the pinned process's cgroup file on a dedicated locked
// thread that is in the pinned host cgroup namespace for the whole read. If
// the thread cannot be restored afterwards it stays locked, so the Go runtime
// retires it instead of reusing a thread in a foreign cgroup namespace.
func (l *linuxLease) readHostCgroup() ([]byte, error) {
	if l.hostCgroup == nil {
		return nil, fmt.Errorf("host cgroup namespace pin required")
	}
	host, err := namespaceIdentity(l.hostCgroup, unix.CLONE_NEWCGROUP)
	if err != nil {
		return nil, err
	}
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		data, restored, err := l.readCgroupIn(host)
		if restored {
			runtime.UnlockOSThread()
		}
		done <- result{data, err}
	}()
	r := <-done
	return r.data, r.err
}
func threadCgroupNamespace() (*os.File, [2]uint64, error) {
	fd, err := unix.Open("/proc/thread-self/ns/cgroup", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, [2]uint64{}, err
	}
	ns := os.NewFile(uintptr(fd), "thread cgroup namespace")
	id, err := namespaceIdentity(ns, unix.CLONE_NEWCGROUP)
	if err != nil {
		return nil, [2]uint64{}, errors.Join(err, ns.Close())
	}
	return ns, id, nil
}
func (l *linuxLease) readCgroupIn(host [2]uint64) (data []byte, restored bool, err error) {
	own, current, err := threadCgroupNamespace()
	if err != nil {
		return nil, true, err
	}
	defer func() { err = errors.Join(err, own.Close()) }()
	if current == host {
		data, err = l.read("cgroup")
		return data, true, err
	}
	if err := unix.Setns(int(l.hostCgroup.Fd()), unix.CLONE_NEWCGROUP); err != nil {
		return nil, true, fmt.Errorf("entering host cgroup namespace: %w", err)
	}
	data, err = l.read("cgroup")
	if restoreErr := restoreThreadCgroupNamespace(int(own.Fd())); restoreErr != nil {
		return nil, false, errors.Join(err, fmt.Errorf("restoring agent cgroup namespace: %w", restoreErr))
	}
	// Confirm the restore before the thread may return to the scheduler.
	after, id, verifyErr := threadCgroupNamespace()
	if verifyErr == nil {
		verifyErr = after.Close()
		if id != current {
			verifyErr = errors.Join(verifyErr, fmt.Errorf("agent cgroup namespace not restored"))
		}
	}
	if verifyErr != nil {
		return nil, false, errors.Join(err, verifyErr)
	}
	return data, true, err
}
func (l *linuxLease) Close() error {
	var errs []error
	for _, f := range []*os.File{l.namespace, l.cgroup, l.hostCgroup, l.proc} {
		if f != nil {
			errs = append(errs, f.Close())
		}
	}
	l.namespace, l.cgroup, l.hostCgroup, l.proc = nil, nil, nil, nil
	return errors.Join(errs...)
}
