// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package rootbarrier

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

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
	// Without the barrier: EINVAL or ELOOP, the root is moved onto itself.
	{OpMoveMount, func() error { return unix.MoveMount(unix.AT_FDCWD, "/", unix.AT_FDCWD, "/", 0) }},
	// Without the barrier: EINVAL, MNT_EXPIRE with MNT_DETACH (checked after
	// the hook, so the root is never unmounted or remounted).
	{OpUmount, func() error { return unix.Unmount("/", unix.MNT_EXPIRE|unix.MNT_DETACH) }},
	// The capable branch of the new mount API. Without the barrier: a
	// filesystem context, closed at once.
	{OpNewMount, func() error {
		fd, err := unix.Fsopen("tmpfs", unix.FSOPEN_CLOEXEC)
		if err == nil {
			unix.Close(fd)
		}
		return err
	}},
	// Without the barrier: the child starts, its exec fails with ENOENT and
	// it exits.
	{OpCloneNS, func() error { return forkExecMissing(unix.CLONE_NEWNS) }},
	{OpUserns, func() error { return forkExecMissing(unix.CLONE_NEWUSER) }},
	// Last: without the barrier, this thread gets its own mount namespace
	// (and fs_struct). The thread is never the main thread and exits after
	// the test, so the process is not changed.
	{OpUnshareNS, func() error { return unix.Unshare(unix.CLONE_NEWNS) }},
}

func forkExecMissing(flags uintptr) error {
	_, err := syscall.ForkExec(missingPath, []string{missingPath}, &syscall.ProcAttr{Sys: &syscall.SysProcAttr{Cloneflags: flags}})
	return err
}

var selfTestMu sync.Mutex

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
		if unix.Gettid() != unix.Getpid() {
			result <- selfTestOnThread(probeMap)
			return
		}
		// Go never ends the main thread, whose name is also the process
		// name. Keep it locked to this goroutine, so the probes run on
		// another thread, and release it unchanged.
		inner := make(chan error, 1)
		go func() {
			runtime.LockOSThread()
			inner <- selfTestOnThread(probeMap)
		}()
		err := <-inner
		runtime.UnlockOSThread()
		result <- err
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
	// The nonce becomes this thread's name, so the entry matches only this
	// thread, also after a later thread reuses its id.
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("root barrier: probe nonce: %w", err)
	}
	// 15 characters and the NUL: the kernel keeps 15.
	copy(entry.Nonce[:15], hex.EncodeToString(random))
	if err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&entry.Nonce[0])), 0, 0, 0); err != nil {
		return fmt.Errorf("root barrier: setting the probe thread name: %w", err)
	}
	var errs []error
	for _, p := range probes {
		errs = append(errs, runProbe(probeMap, entry, p))
	}
	if err := ClearProbe(probeMap); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ClearProbe removes the probe entry. SelfTest calls it at its end, and
// VerifyMaps at its start, for an entry that a previous owner left. It
// retries; when it still fails, the error must refuse activation.
func ClearProbe(probeMap *ebpf.Map) error {
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
	result := "no error"
	if runErr != nil {
		result = runErr.Error()
	}
	return fmt.Errorf("root barrier: %s not denied by the barrier (result: %s)", p.op, result)
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
