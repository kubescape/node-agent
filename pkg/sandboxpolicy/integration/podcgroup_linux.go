package integration

import (
	"fmt"
	"os"
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
