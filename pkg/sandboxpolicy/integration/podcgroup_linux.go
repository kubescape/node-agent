package integration

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// cgroupID returns the cgroup ID (the inode) of the cgroup v2 directory rel
// under root. Symlinks and paths outside root are refused.
func cgroupID(root, rel string) (uint64, error) {
	dir, err := os.Open(root)
	if err != nil {
		return 0, err
	}
	defer dir.Close()
	fd, err := unix.Openat2(int(dir.Fd()), strings.TrimPrefix(rel, "/"), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return 0, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return 0, fmt.Errorf("%s is not on cgroup v2", rel)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}

// readPauseCgroup runs read (the pause process's /proc/<pid>/cgroup) under a
// pidfd taken before it, and refuses the result when the process exited
// meanwhile: its PID may then name another process. The pidfd is taken in
// node-agent's PID namespace, which is the host's (hostPID).
func readPauseCgroup(pid uint32, read func() ([]byte, error)) (data []byte, err error) {
	if pid == 0 {
		return nil, fmt.Errorf("no PID")
	}
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd_open %d: %w", pid, err)
	}
	defer func() {
		if closeErr := unix.Close(fd); closeErr != nil {
			data, err = nil, errors.Join(err, closeErr)
		}
	}()
	data, err = read()
	if err != nil {
		return nil, err
	}
	if err := unix.PidfdSendSignal(fd, 0, nil, 0); err != nil {
		return nil, fmt.Errorf("process %d exited during the read: %w", pid, err)
	}
	return data, nil
}

// HostPIDNamespace checks that procRoot is a procfs of node-agent's own PID
// namespace: procRoot/self resolves to os.Getpid(), and procRoot/self/ns/pid
// names the same PID namespace (inode) as /proc/self/ns/pid (S4 review v3,
// LOW 3/4: equal numbers alone could come from another namespace).
// readPauseCgroup takes its pidfd in node-agent's PID namespace and reads
// through procRoot, so both must name the same processes (hostPID). S5
// calls it before it wires the pod cgroup resolver, and again at every NRI
// registration.
func HostPIDNamespace(procRoot string) error {
	return samePIDNamespace(procRoot, "/proc")
}

// samePIDNamespace is HostPIDNamespace with node-agent's own procfs (tests).
func samePIDNamespace(procRoot, ownProc string) error {
	self, err := os.Readlink(filepath.Join(procRoot, "self"))
	if err != nil {
		return fmt.Errorf("%s/self: %w", procRoot, err)
	}
	if self != strconv.Itoa(os.Getpid()) {
		return fmt.Errorf("%s/self is %q, not this process (%d): not node-agent's PID namespace", procRoot, self, os.Getpid())
	}
	theirs, err := os.Readlink(filepath.Join(procRoot, "self/ns/pid"))
	if err != nil {
		return fmt.Errorf("%s/self/ns/pid: %w", procRoot, err)
	}
	ours, err := os.Readlink(filepath.Join(ownProc, "self/ns/pid"))
	if err != nil {
		return fmt.Errorf("%s/self/ns/pid: %w", ownProc, err)
	}
	if theirs != ours {
		return fmt.Errorf("%s/self/ns/pid is %q, not node-agent's %q: not node-agent's PID namespace", procRoot, theirs, ours)
	}
	return nil
}
