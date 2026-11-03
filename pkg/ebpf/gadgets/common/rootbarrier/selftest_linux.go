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

// SelfTest covers one thread of this process through the probe map and runs
// each probe on it. Each probe must fail with EPERM and add one to the
// matching counter, so a denial by another layer does not count. The process
// needs CAP_SYS_ADMIN and CAP_SYS_CHROOT, else the kernel denies a probe
// before the barrier sees it.
func SelfTest(counters, probeMap *ebpf.Map) error {
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
		result <- selfTestOnThread(counters, probeMap)
	}()
	return <-result
}

func selfTestOnThread(counters, probeMap *ebpf.Map) error {
	if err := probeMap.Put(uint32(0), uint32(unix.Gettid())); err != nil {
		return fmt.Errorf("root barrier: writing probe map: %w", err)
	}
	var errs []error
	for _, p := range probes {
		errs = append(errs, runProbe(counters, p))
	}
	if err := probeMap.Put(uint32(0), uint32(0)); err != nil {
		errs = append(errs, fmt.Errorf("root barrier: clearing probe map: %w", err))
	}
	return errors.Join(errs...)
}

func runProbe(counters *ebpf.Map, p probe) error {
	before, err := denials(counters, p.op)
	if err != nil {
		return err
	}
	runErr := p.run()
	after, err := denials(counters, p.op)
	if err != nil {
		return err
	}
	if !errors.Is(runErr, unix.EPERM) || after == before {
		return fmt.Errorf("root barrier: %s not denied by the barrier (result %v, %d new denials)", p.op, runErr, after-before)
	}
	return nil
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
