package igbackend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"golang.org/x/sys/unix"
)

// LinuxValidator uses host-visible procfs and the unified cgroup mount. Runtime
// and container ID must originate from the authoritative runtime cache; neither
// is inferred from cgroup names. Nonempty roots support node-agent host mounts.
type LinuxValidator struct{ ProcRoot, CgroupRoot string }
type linuxLease struct {
	proc, cgroup, namespace *os.File
	identity                sandboxpolicy.Binding
	start                   string
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
	root, err := os.Open(cgRoot)
	if err != nil {
		return fail(err)
	}
	fd, err := unix.Openat2(int(root.Fd()), strings.TrimPrefix(b.CgroupPath, "/"), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
	root.Close()
	if err != nil {
		return fail(err)
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
func (l *linuxLease) read(name string) ([]byte, error) {
	fd, err := unix.Openat(int(l.proc.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
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
func (l *linuxLease) Check() error {
	start, err := l.readStart()
	if err != nil {
		return err
	}
	if start != l.start {
		return fmt.Errorf("process identity changed")
	}
	data, err := l.read("cgroup")
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
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Ino != l.identity.MountNamespace {
		return fmt.Errorf("process mount namespace changed")
	}
	return nil
}
func (l *linuxLease) Close() error {
	var errs []error
	for _, f := range []*os.File{l.namespace, l.cgroup, l.proc} {
		if f != nil {
			errs = append(errs, f.Close())
		}
	}
	l.namespace, l.cgroup, l.proc = nil, nil, nil
	return errors.Join(errs...)
}
