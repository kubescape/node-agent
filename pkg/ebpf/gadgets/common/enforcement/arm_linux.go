// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// pidfdThread is PIDFD_THREAD (Linux 6.9+): a pidfd for a single thread.
const pidfdThread = unix.O_EXCL

// ArmExisting arms the tasks that already run in a bound container cgroup and
// its child cgroups. The BPF program arms tasks only at exec, so without this a
// container that started before the gadget would not be judged until its next
// exec.
//
// Tasks in the host mount namespace (a runtime helper such as runc init for
// exec, caught between entering the cgroup and joining the container) are
// skipped, as in the BPF arming rule. On kernels without PIDFD_THREAD, only
// thread group leaders are armed; the BPF rule treats their threads as armed.
//
// A task can fork between the read of cgroup.threads and its own arming; its
// child is then not armed by inheritance. So the walk repeats until a pass
// arms no new task. It returns ErrContainerGone when the cgroup no longer
// exists.
func ArmExisting(armed Map, cgroupPath string) error {
	hostMntns, err := mntnsOf("1")
	if err != nil {
		return err
	}
	root := filepath.Join(host.HostRoot, "sys/fs/cgroup", cgroupPath)
	seen := map[int]bool{}
	for pass := 0; pass < maxArmingPasses; pass++ {
		before := len(seen)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if path == root {
					if errors.Is(err, fs.ErrNotExist) {
						return ErrContainerGone
					}
					return fmt.Errorf("listing container tasks: %w", err)
				}
				if errors.Is(err, fs.ErrNotExist) {
					return nil // a child cgroup removed during the walk
				}
				return fmt.Errorf("listing container tasks: %w", err)
			}
			if !d.IsDir() {
				return nil
			}
			return armThreads(armed, filepath.Join(path, "cgroup.threads"), hostMntns, seen)
		})
		if err != nil {
			return err
		}
		if len(seen) == before {
			return nil
		}
	}
	return fmt.Errorf("container tasks still changing after %d arming passes", maxArmingPasses)
}

// ErrContainerGone means the container's cgroup no longer exists.
var ErrContainerGone = errors.New("container cgroup is gone")

const maxArmingPasses = 8

func armThreads(armed Map, threads string, hostMntns uint64, seen map[int]bool) error {
	f, err := os.Open(threads)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // the cgroup was removed
	}
	if err != nil {
		return fmt.Errorf("listing container tasks: %w", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		tid, err := strconv.Atoi(scanner.Text())
		if err != nil || seen[tid] {
			continue
		}
		// A task is seen once it is armed or needs no arming; any other
		// failure is returned, so the caller does not report it protected.
		mntns, err := mntnsOf(scanner.Text())
		if errors.Is(err, fs.ErrNotExist) || (err == nil && mntns == hostMntns) {
			seen[tid] = true // exited, or a runtime helper
			continue
		}
		if err != nil {
			return fmt.Errorf("reading mount namespace of task %d: %w", tid, err)
		}
		fd, err := unix.PidfdOpen(tid, pidfdThread)
		if errors.Is(err, unix.EINVAL) {
			fd, err = unix.PidfdOpen(tid, 0)
		}
		if errors.Is(err, unix.EINVAL) {
			// A non-leader thread on a kernel without PIDFD_THREAD: the
			// BPF rule judges it through its group leader, which can be
			// outside this cgroup, so arm the leader.
			fd, err = openLeader(scanner.Text(), hostMntns)
		}
		if errors.Is(err, unix.ESRCH) || errors.Is(err, fs.ErrNotExist) {
			seen[tid] = true // exited
			continue
		}
		if err != nil {
			return fmt.Errorf("opening task %d: %w", tid, err)
		}
		err = armed.Put(uint32(fd), uint32(1))
		unix.Close(fd)
		if err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("arming task %d: %w", tid, err)
		}
		seen[tid] = true
	}
	return scanner.Err()
}

// openLeader opens a pidfd of the thread group leader of tid. A leader in the
// runtime mount namespace is a runtime helper: arming it would judge the
// runtime, so the thread cannot be armed and the caller gets an error.
func openLeader(tid string, hostMntns uint64) (int, error) {
	data, err := os.ReadFile(filepath.Join(host.HostProcFs, tid, "status"))
	if err != nil {
		return -1, err
	}
	tgid := -1
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
			tgid, err = strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return -1, fmt.Errorf("reading leader of task %s: %w", tid, err)
			}
		}
	}
	if tgid <= 0 {
		return -1, fmt.Errorf("no leader for task %s", tid)
	}
	mntns, err := mntnsOf(strconv.Itoa(tgid))
	if err != nil {
		return -1, err
	}
	if mntns == hostMntns {
		return -1, fmt.Errorf("thread %s has a runtime helper as leader", tid)
	}
	return unix.PidfdOpen(tgid, 0)
}

// RuntimeMountNamespace is the mount namespace of PID 1 as this process sees
// it: the namespace the container runtime runs in. Pass it to the gadget's
// host_mntns_id so the BPF arming rule and ArmExisting agree.
func RuntimeMountNamespace() (uint64, error) { return mntnsOf("1") }

func mntnsOf(pid string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(host.HostProcFs, pid, "ns/mnt"), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}
