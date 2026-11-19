package integration

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/google/uuid"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"golang.org/x/sys/unix"
)

// FenceCgroups pins the API-identified pod and its container. IDs are full kernel
// cgroup handles, not truncated inode numbers. The caller owns Close.
type FenceCgroups struct {
	Pod, Container     *os.File
	PodID, ContainerID uint64
}

func (c *FenceCgroups) Close() error {
	var errs []error
	for _, f := range []*os.File{c.Container, c.Pod} {
		if f != nil {
			errs = append(errs, f.Close())
		}
	}
	c.Container, c.Pod = nil, nil
	return errors.Join(errs...)
}

// OpenFenceCgroups resolves only standard kubelet cgroupfs/systemd pod layouts
// under a caller-trusted host cgroup-v2 mount. The binding must first pass the
// live process identity validator; this helper does not attest PID membership.
// Child lookup is relative to the pinned pod, never an independently reopened
// absolute path. Unsupported layouts and mount crossings fail closed.
func OpenFenceCgroups(root string, binding sandboxpolicy.Binding) (*FenceCgroups, error) {
	podPath, childPath, err := fenceCgroupPaths(string(binding.PodUID), binding.CgroupPath)
	if err != nil {
		return nil, err
	}
	if !path.IsAbs(root) || path.Clean(root) != root || binding.CgroupID == 0 {
		return nil, fmt.Errorf("trusted absolute cgroup root and binding identity required")
	}
	rootFD, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	var fs unix.Statfs_t
	if err = unix.Fstatfs(rootFD, &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, fmt.Errorf("trusted root is not cgroup v2")
	}
	open := func(base int, name string) (*os.File, error) {
		fd, err := unix.Openat2(base, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), name), nil
	}
	c := &FenceCgroups{}
	fail := func(err error) (*FenceCgroups, error) { return nil, errors.Join(err, c.Close()) }
	c.Pod, err = open(rootFD, strings.TrimPrefix(podPath, "/"))
	if err != nil {
		return fail(err)
	}
	c.Container, err = open(int(c.Pod.Fd()), childPath)
	if err != nil {
		return fail(err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(int(c.Container.Fd()), &st); err != nil {
		return fail(err)
	}
	// Runtime discovery and LinuxValidator use stat inode identity. The fence uses
	// the full file handle separately (some kernels encode generation bits).
	if st.Ino != binding.CgroupID {
		return fail(fmt.Errorf("container cgroup inode changed"))
	}
	c.PodID, err = restartfence.PodCgroupID(c.Pod)
	if err != nil {
		return fail(err)
	}
	c.ContainerID, err = restartfence.PodCgroupID(c.Container)
	if err != nil {
		return fail(err)
	}
	if c.PodID == c.ContainerID {
		return fail(fmt.Errorf("container is not below pod"))
	}
	return c, nil
}

func fenceCgroupPaths(uid, containerPath string) (string, string, error) {
	parsed, err := uuid.Parse(uid)
	if err != nil || parsed.String() != uid {
		return "", "", fmt.Errorf("canonical API pod UID required")
	}
	if !path.IsAbs(containerPath) || path.Clean(containerPath) != containerPath || containerPath == "/" {
		return "", "", fmt.Errorf("clean absolute container cgroup path required")
	}
	parts := strings.Split(strings.TrimPrefix(containerPath, "/"), "/")
	podIndex := -1
	for i, p := range parts {
		matched := false
		if p == "pod"+uid && i >= 1 {
			matched = parts[i-1] == "kubepods" || (i >= 2 && parts[i-2] == "kubepods" && (parts[i-1] == "burstable" || parts[i-1] == "besteffort"))
		}
		systemUID := strings.ReplaceAll(uid, "-", "_")
		if i >= 1 && p == "kubepods-pod"+systemUID+".slice" && parts[i-1] == "kubepods.slice" {
			matched = true
		}
		for _, qos := range []string{"burstable", "besteffort"} {
			if i >= 2 && p == "kubepods-"+qos+"-pod"+systemUID+".slice" && parts[i-1] == "kubepods-"+qos+".slice" && parts[i-2] == "kubepods.slice" {
				matched = true
			}
		}
		if matched {
			if podIndex >= 0 {
				return "", "", fmt.Errorf("ambiguous pod ancestry")
			}
			podIndex = i
		}
	}
	if podIndex < 0 || podIndex == len(parts)-1 {
		return "", "", fmt.Errorf("container has no verified kubelet pod ancestor")
	}
	return "/" + strings.Join(parts[:podIndex+1], "/"), strings.Join(parts[podIndex+1:], "/"), nil
}
