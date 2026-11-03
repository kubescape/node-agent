// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// missingPath must not exist. Probes that would act on it fail with ENOENT
// when the barrier does not deny first.
const missingPath = "/nonexistent-root-barrier-probe"

// A probe is one operation the barrier must deny. Without the barrier each
// probe fails for another reason, or has no effect: the self-test never
// changes the root or the mount tree of the process.
type probe struct {
	op  Op
	run func() error
}

var probes = []probe{
	// Without the barrier: EINVAL, the threads of this process share
	// fs_struct (mntns_install).
	{OpSetns, func() error {
		fd, err := unix.Open("/proc/thread-self/ns/mnt", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("probe setup: %w", err)
		}
		defer unix.Close(fd)
		return unix.Setns(fd, unix.CLONE_NEWNS)
	}},
	// Without the barrier: the same root again.
	{OpChroot, func() error { return unix.Chroot("/") }},
	// Without the barrier: EBUSY or EINVAL, the new root is the current root.
	{OpPivotRoot, func() error { return unix.PivotRoot("/", "/") }},
	// Without the barrier: ENOENT for the source.
	{OpMount, func() error { return unix.Mount(missingPath, "/", "", unix.MS_MOVE, "") }},
	// Without the barrier: the child starts, its exec fails with ENOENT and
	// it exits.
	{OpCloneNS, func() error { return forkExecMissing(unix.CLONE_NEWNS) }},
	{OpUserns, func() error { return forkExecMissing(unix.CLONE_NEWUSER) }},
}

func forkExecMissing(flags uintptr) error {
	_, err := syscall.ForkExec(missingPath, []string{missingPath}, &syscall.ProcAttr{Sys: &syscall.SysProcAttr{Cloneflags: flags}})
	return err
}

var selfTestMu sync.Mutex

// probeEntry matches struct root_barrier_probe in ../root_barrier.h.
type probeEntry struct {
	Tid      uint32
	Denied   uint32
	PidnsDev uint64
	PidnsIno uint64
}

// SelfTest covers one thread of this process through the probe map and runs
// each probe on it. Each probe must fail with EPERM and the barrier must mark
// the probe's operation in the probe entry, so a denial by another layer, or a
// barrier denial of another task, does not count. The process needs
// CAP_SYS_ADMIN and CAP_SYS_CHROOT, else the kernel denies a probe before the
// barrier sees it.
func SelfTest(probeMap *ebpf.Map) error {
	if err := needCapabilities(); err != nil {
		return err
	}
	selfTestMu.Lock()
	defer selfTestMu.Unlock()
	result := make(chan error, 1)
	go func() {
		// The thread is never unlocked, so it exits with this goroutine:
		// no other goroutine runs on a thread that ran a probe.
		runtime.LockOSThread()
		result <- selfTestOnThread(probeMap)
	}()
	return <-result
}

func selfTestOnThread(probeMap *ebpf.Map) error {
	// The BPF side matches the thread id in this thread's PID namespace, so
	// the test also works outside the host PID namespace.
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/pid", &st); err != nil {
		return fmt.Errorf("root barrier: reading the PID namespace: %w", err)
	}
	entry := probeEntry{
		Tid: uint32(unix.Gettid()),
		// The kernel's dev_t encoding (MINORBITS 20), not the stat encoding.
		PidnsDev: uint64(unix.Major(st.Dev))<<20 | uint64(unix.Minor(st.Dev)),
		PidnsIno: st.Ino,
	}
	var errs []error
	for _, p := range probes {
		errs = append(errs, runProbe(probeMap, entry, p))
	}
	if err := clearProbe(probeMap); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// clearProbe retries, because a stale thread id could cover a later task with
// the same id. When it still fails, the error refuses activation and the
// instance, with its probe map, is removed.
func clearProbe(probeMap *ebpf.Map) error {
	var err error
	for i := 0; i < 3; i++ {
		if err = probeMap.Put(uint32(0), probeEntry{}); err == nil {
			return nil
		}
	}
	return fmt.Errorf("root barrier: clearing probe map: %w", err)
}

func runProbe(probeMap *ebpf.Map, entry probeEntry, p probe) error {
	if err := probeMap.Put(uint32(0), entry); err != nil {
		return fmt.Errorf("root barrier: writing probe map: %w", err)
	}
	runErr := p.run()
	var after probeEntry
	if err := probeMap.Lookup(uint32(0), &after); err != nil {
		return fmt.Errorf("root barrier: reading probe map: %w", err)
	}
	if errors.Is(runErr, unix.EPERM) && after.Denied&(1<<p.op) != 0 {
		return nil
	}
	if p.op == OpUserns && errors.Is(runErr, unix.ENOSPC) {
		return fmt.Errorf("root barrier: user namespaces are disabled on this node (user.max_user_namespaces), so the userns probe cannot reach the barrier")
	}
	return fmt.Errorf("root barrier: %s not denied by the barrier (result %v)", p.op, runErr)
}

func needCapabilities() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("root barrier: reading capabilities: %w", err)
	}
	for _, c := range []uint{unix.CAP_SYS_ADMIN, unix.CAP_SYS_CHROOT} {
		if data[c/32].Effective&(1<<(c%32)) == 0 {
			return fmt.Errorf("root barrier: self-test needs CAP_SYS_ADMIN and CAP_SYS_CHROOT")
		}
	}
	return nil
}
