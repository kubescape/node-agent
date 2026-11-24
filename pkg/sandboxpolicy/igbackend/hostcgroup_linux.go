package igbackend

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// ReadHostProcessCgroup reads <procRoot>/<pid>/cgroup with LinuxValidator's
// reader: on a locked thread in the pinned initial cgroup namespace of
// procRoot's PID 1 (readHostCgroup), so the paths are host paths even when
// the agent runs in a private cgroup namespace. procRoot must be procfs. It
// returns the file as read; the caller checks that pid is still the process
// it means.
func ReadHostProcessCgroup(procRoot string, pid uint32) (data []byte, err error) {
	if pid == 0 {
		return nil, fmt.Errorf("no PID")
	}
	proc, err := os.Open(filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10)))
	if err != nil {
		return nil, err
	}
	l := &linuxLease{proc: proc}
	defer func() { err = errors.Join(err, l.Close()) }()
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(proc.Fd()), &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, fmt.Errorf("process root is not procfs")
	}
	if l.hostCgroup, err = pinInitialCgroupNamespace(procRoot); err != nil {
		return nil, err
	}
	return l.readHostCgroup()
}
