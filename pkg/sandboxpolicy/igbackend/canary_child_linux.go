//go:build linux

package igbackend

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The canary child: this binary run as `<exe> __sandbox-section-canary
// <hook,hook,...> <dir>` (sectionCanary.runChild). It makes one harmless call
// per requested hook and exits 0. The parent decides from the BPF run counts:
// most calls fail after their hook (ENOENT, EINVAL, EBUSY), and that is
// expected. A call refused with EPERM, EACCES or ENOSYS may have been stopped
// before the hook (seccomp, a missing capability, another LSM), and so may a
// call whose fixture could not be made (canaryRefusal has the per-hook
// exceptions), so the child lists those hooks in <dir>/results
// (canaryResults). The child exits in init,
// before main, so node-agent itself never starts in it.
//
// "Harmless": each call either fails after its hook, or changes only the
// child's own state or files in <dir>, which the parent removes. The mount calls are
// the root barrier self-test's probes (pkg/ebpf/gadgets/common/rootbarrier):
// each fails, or does nothing, without the barrier.

func init() {
	if len(os.Args) == 4 && os.Args[1] == canaryArg {
		os.Exit(runCanaryChild(strings.Split(os.Args[2], ","), os.Args[3]))
	}
}

// canaryResultsFile lists, one per line, "<hook> <errno>" (or
// "<hook> fixture-<errno>") for each requested hook whose every call was
// refused (canaryRefusal).
const canaryResultsFile = "results"

// canaryMissing is a name never made in the child's private work directory:
// an exec of it fails after its fork.
const canaryMissing = "missing"

// canaryFixtureError: something the call needs (a file, an io_uring ring)
// could not be made or used, so the call may fail before its hook.
type canaryFixtureError struct{ err error }

func (e canaryFixtureError) Error() string { return "fixture: " + e.err.Error() }

// canaryFixture makes an empty file for a trigger.
func canaryFixture(path string) error {
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		return canaryFixtureError{err}
	}
	return nil
}

// canarySeccomp reports whether a seccomp filter applies to this process
// (/proc/self/status "Seccomp:" other than 0). Unreadable: true (fail toward
// "not proven" only for the one hook that uses it).
var canarySeccomp = func() bool { return canarySeccompIn(os.ReadFile("/proc/self/status")) }

// canarySeccompIn reads the "Seccomp:" line of a /proc/<pid>/status. An
// error or no such line: true.
func canarySeccompIn(b []byte, err error) bool {
	if err != nil {
		return true
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Seccomp:"); ok {
			return strings.TrimSpace(v) != "0"
		}
	}
	return true
}

// canaryRefusal returns how hook's call may have been stopped before the
// hook, or "" when the call reached it. ENOSPC comes before the hook only
// for userns_create (the user namespace quota); the file calls get it after
// their hooks on a full disk. A fork's EAGAIN from RLIMIT_NPROC or the
// thread limit comes after cred_prepare but before security_task_alloc, and
// any fork EAGAIN comes before the child's PTRACE_TRACEME. cred_alloc_blank's call always gets EPERM after
// the hook (the parent is multithreaded), so its EPERM counts only under a
// seccomp filter, which can refuse keyctl before the hook.
func canaryRefusal(hook string, err error) string {
	var fixture canaryFixtureError
	if errors.As(err, &fixture) {
		if e, ok := fixture.err.(syscall.Errno); ok {
			return "fixture-" + unix.ErrnoName(e)
		}
		var pe *os.PathError
		if errors.As(fixture.err, &pe) {
			if e, ok := pe.Err.(syscall.Errno); ok {
				return "fixture-" + unix.ErrnoName(e)
			}
		}
		return "fixture"
	}
	e, ok := err.(syscall.Errno)
	switch {
	case !ok:
		return ""
	case e == unix.EPERM && hook == "cred_alloc_blank":
		if !canarySeccomp() {
			return ""
		}
	case e == unix.ENOSPC:
		if hook != "userns_create" {
			return ""
		}
	case e == unix.EAGAIN:
		if hook != "task_alloc" && hook != "ptrace_traceme" {
			return ""
		}
	case e != unix.EPERM && e != unix.EACCES && e != unix.ENOSYS:
		return ""
	}
	return unix.ErrnoName(e)
}

// A canaryTrigger is one harmless call and the hooks it passes through. The
// triggers run in this order.
type canaryTrigger struct {
	hooks []string
	run   func(dir string) error
}

var canaryTriggers = []canaryTrigger{
	// The child's own exec passed both bprm hooks.
	{[]string{"bprm_check_security", "bprm_committed_creds"}, func(string) error { return nil }},
	{[]string{"task_alloc", "cred_prepare", "cred_free"}, func(d string) error { return canaryForkExec(d, 0, false) }},
	// ENOSPC: no user namespace quota left, before the hook.
	{[]string{"userns_create"}, func(d string) error { return canaryForkExec(d, unix.CLONE_NEWUSER, false) }},
	// The traced child fails its exec and exits: no stop is reported.
	{[]string{"ptrace_traceme"}, func(d string) error { return canaryForkExec(d, 0, true) }},
	{[]string{"file_open"}, func(string) error { return canaryClose(unix.Open("/proc/self/exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)) }},
	// Before a new session keyring: on success the parent gets the keyring
	// it already has. node-agent is multithreaded, so the kernel refuses it
	// (EPERM) after the hook. A seccomp filter can also refuse it (EPERM)
	// before the hook: then a silent hook is not proven (canaryRefusal). A
	// keyring permission refusal is EACCES.
	{[]string{"cred_alloc_blank"}, func(string) error {
		_, err := unix.KeyctlInt(unix.KEYCTL_SESSION_TO_PARENT, 0, 0, 0, 0)
		return err
	}},
	// A new anonymous session keyring of this child only.
	{[]string{"key_alloc"}, func(string) error {
		_, _, e := unix.Syscall(unix.SYS_KEYCTL, unix.KEYCTL_JOIN_SESSION_KEYRING, 0, 0)
		return errnoErr(e)
	}},
	{[]string{"key_permission"}, func(string) error {
		_, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, unix.KEY_SPEC_SESSION_KEYRING)
		return err
	}},
	{[]string{"capset"}, func(string) error {
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var data [2]unix.CapUserData
		if err := unix.Capget(&hdr, &data[0]); err != nil {
			return err
		}
		return unix.Capset(&hdr, &data[0])
	}},
	// One thread, its own IDs again.
	{[]string{"task_fix_setuid"}, func(string) error {
		_, _, e := unix.RawSyscall(unix.SYS_SETUID, uintptr(unix.Getuid()), 0, 0)
		return errnoErr(e)
	}},
	{[]string{"task_fix_setgid"}, func(string) error {
		_, _, e := unix.RawSyscall(unix.SYS_SETGID, uintptr(unix.Getgid()), 0, 0)
		return errnoErr(e)
	}},
	{[]string{"ptrace_access_check"}, func(string) error {
		return canaryClose(unix.Open(fmt.Sprintf("/proc/%d/environ", os.Getppid()), unix.O_RDONLY|unix.O_CLOEXEC, 0))
	}},
	{[]string{"bpf"}, func(string) error {
		var attr [12]byte // BPF_PROG_GET_NEXT_ID from 0
		_, _, e := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_GET_NEXT_ID, uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
		return errnoErr(e)
	}},
	{[]string{"perf_event_open"}, func(string) error {
		attr := unix.PerfEventAttr{Type: unix.PERF_TYPE_SOFTWARE, Config: unix.PERF_COUNT_SW_DUMMY,
			Bits: unix.PerfBitDisabled | unix.PerfBitExcludeKernel | unix.PerfBitExcludeHv}
		attr.Size = uint32(unsafe.Sizeof(attr))
		return canaryClose(unix.PerfEventOpen(&attr, 0, -1, -1, unix.PERF_FLAG_FD_CLOEXEC))
	}},
	{[]string{"inode_init_security_anon"}, func(string) error {
		fd, _, e := unix.Syscall(unix.SYS_USERFAULTFD, unix.O_CLOEXEC, 0, 0)
		if e == 0 {
			_ = unix.Close(int(fd))
		}
		return errnoErr(e)
	}},
	// io_uring_setup also creates a secure anonymous inode.
	{[]string{"inode_init_security_anon"}, func(string) error {
		var p ioUringParams
		return canaryClose(canaryUringSetup(&p))
	}},
	{[]string{"uring_override_creds"}, func(string) error { return canaryUringPersonality() }},
	// The root barrier probes (each fails, or changes nothing).
	{[]string{"path_chroot", "capable"}, func(string) error { return unix.Chroot("/") }},
	{[]string{"sb_pivotroot"}, func(string) error { return unix.PivotRoot("/", "/") }},
	{[]string{"sb_mount"}, func(d string) error { return unix.Mount(filepath.Join(d, canaryMissing), "/", "", unix.MS_MOVE, "") }},
	{[]string{"move_mount"}, func(string) error { return unix.MoveMount(unix.AT_FDCWD, "/", unix.AT_FDCWD, "/", 0) }},
	{[]string{"sb_umount"}, func(string) error { return unix.Unmount("/", unix.MNT_EXPIRE|unix.MNT_DETACH) }},
	// A tmpfs superblock that is never mounted; closing the fd drops it.
	{[]string{"sb_kern_mount"}, func(string) error {
		fd, err := unix.Fsopen("tmpfs", unix.FSOPEN_CLOEXEC)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.FsconfigCreate(fd)
	}},
	// Network: AF_UNIX only, no packet leaves the node.
	{[]string{"socket_connect"}, func(string) error {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Connect(fd, &unix.SockaddrUnix{Name: fmt.Sprintf("@kubescape-sandbox-canary-%d", os.Getpid())})
	}},
	{[]string{"socket_sendmsg"}, func(string) error {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fds[0])
		defer unix.Close(fds[1])
		return unix.Sendmsg(fds[0], []byte{0}, nil, nil, 0)
	}},
	// Files: all in the child's temporary directory.
	{[]string{"path_truncate"}, func(d string) error { return unix.Truncate(filepath.Join(d, "f"), 0) }},
	{[]string{"path_chmod", "inode_setattr"}, func(d string) error { return unix.Chmod(filepath.Join(d, "f"), 0o600) }},
	{[]string{"path_chown"}, func(d string) error { return unix.Chown(filepath.Join(d, "f"), unix.Getuid(), unix.Getgid()) }},
	{[]string{"inode_setxattr"}, func(d string) error {
		return unix.Setxattr(filepath.Join(d, "f"), "user.kubescape-canary", []byte("1"), 0)
	}},
	{[]string{"inode_removexattr"}, func(d string) error {
		return unix.Removexattr(filepath.Join(d, "f"), "user.kubescape-canary")
	}},
	{[]string{"inode_set_acl"}, func(d string) error {
		return unix.Setxattr(filepath.Join(d, "f"), "system.posix_acl_access", canaryBaseACL(), 0)
	}},
	{[]string{"inode_remove_acl"}, func(d string) error {
		return unix.Removexattr(filepath.Join(d, "f"), "system.posix_acl_access")
	}},
	{[]string{"path_mknod", "inode_mknod"}, func(d string) error { return unix.Mknod(filepath.Join(d, "p"), unix.S_IFIFO|0o600, 0) }},
	// Each trigger below makes what it needs first, so it does not depend on
	// another trigger having run.
	{[]string{"path_mkdir"}, func(d string) error { return unix.Mkdir(filepath.Join(d, "d"), 0o700) }},
	{[]string{"path_rmdir"}, func(d string) error {
		if err := unix.Mkdir(filepath.Join(d, "r"), 0o700); err != nil {
			return canaryFixtureError{err}
		}
		return unix.Rmdir(filepath.Join(d, "r"))
	}},
	{[]string{"path_symlink"}, func(d string) error { return unix.Symlink("f", filepath.Join(d, "s")) }},
	{[]string{"path_link"}, func(d string) error { return unix.Link(filepath.Join(d, "f"), filepath.Join(d, "l")) }},
	{[]string{"path_rename"}, func(d string) error {
		if err := canaryFixture(filepath.Join(d, "n")); err != nil {
			return err
		}
		return unix.Rename(filepath.Join(d, "n"), filepath.Join(d, "m"))
	}},
	{[]string{"path_unlink"}, func(d string) error {
		if err := canaryFixture(filepath.Join(d, "u")); err != nil {
			return err
		}
		return unix.Unlink(filepath.Join(d, "u"))
	}},
}

// canaryTriggered reports whether a trigger passes through hook.
func canaryTriggered(hook string) bool {
	for _, t := range canaryTriggers {
		for _, h := range t.hooks {
			if h == hook {
				return true
			}
		}
	}
	return false
}

// runCanaryChild runs every trigger of the requested hooks in a new work
// directory under dir, then writes dir/results. It returns 0, or 3 when the
// work directory cannot be made (the file triggers would fail before their
// hooks: unknown, not silent).
func runCanaryChild(hooks []string, dir string) int {
	want := map[string]bool{}
	for _, h := range hooks {
		want[h] = true
	}
	work, err := os.MkdirTemp(dir, "run-")
	if err == nil {
		err = os.WriteFile(filepath.Join(work, "f"), nil, 0o600)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox section canary: work directory: %v\n", err)
		return 3
	}
	defer os.RemoveAll(work)
	refused := map[string]string{} // hook -> errno, while every call was refused
	reached := map[string]bool{}
	for _, t := range canaryTriggers {
		run := false
		for _, h := range t.hooks {
			run = run || want[h]
		}
		if !run {
			continue
		}
		err := t.run(work)
		for _, h := range t.hooks {
			if !want[h] || reached[h] {
				continue
			}
			if why := canaryRefusal(h, err); why != "" {
				refused[h] = why
				continue
			}
			reached[h] = true
			delete(refused, h)
		}
	}
	var out strings.Builder
	for h, e := range refused {
		fmt.Fprintf(&out, "%s %s\n", h, e)
	}
	if err := os.WriteFile(filepath.Join(dir, canaryResultsFile), []byte(out.String()), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox section canary: results: %v\n", err)
		return 3
	}
	return 0
}

// canaryResults reads the hooks whose calls were all refused (hook ->
// errno). A missing or unreadable file gives none: every silent hook then
// stays silent (fail closed).
func canaryResults(dir string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(dir, canaryResultsFile))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if hook, errno, ok := strings.Cut(line, " "); ok {
			out[hook] = errno
		}
	}
	return out
}

// canaryForkExec forks a child (with flags) whose exec of canaryMissing in
// dir fails, so it exits at once; ForkExec reaps it. traced: the child calls
// PTRACE_TRACEME first. Pdeathsig: if the canary child is killed (its
// deadline) before the reap, the grandchild dies too, and is not left for a
// PID 1 that does not reap.
func canaryForkExec(dir string, flags uintptr, traced bool) error {
	path := filepath.Join(dir, canaryMissing)
	_, err := syscall.ForkExec(path, []string{path},
		&syscall.ProcAttr{Sys: &syscall.SysProcAttr{Cloneflags: flags, Ptrace: traced, Pdeathsig: syscall.SIGKILL}})
	return err
}

func canaryClose(fd int, err error) error {
	if err == nil {
		_ = unix.Close(fd)
	}
	return err
}

func errnoErr(e syscall.Errno) error {
	if e == 0 {
		return nil
	}
	return e
}

// canaryBaseACL is a POSIX ACL with only the three base entries (the file's
// own mode): setting it changes nothing.
func canaryBaseACL() []byte {
	const undefined = 0xffffffff
	b := binary.LittleEndian.AppendUint32(nil, 2)                                     // POSIX_ACL_XATTR_VERSION
	for _, e := range []struct{ tag, perm uint16 }{{0x01, 6}, {0x04, 0}, {0x20, 0}} { // USER_OBJ rw, GROUP_OBJ, OTHER
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, undefined)
	}
	return b
}

// io_uring ABI (include/uapi/linux/io_uring.h).
const (
	ioringRegisterPersonality = 9
	ioringOffSQES             = 0x10000000
	ioringOffCQRing           = 0x8000000
	ioringOpNop               = 0
	ioringSQESize             = 64
	ioringCQESize             = 16
	ioringEnterGetEvents      = 1
)

type ioUringParams struct {
	SQEntries, CQEntries, Flags, SQThreadCPU, SQThreadIdle, Features, WQFd uint32
	Resv                                                                   [3]uint32
	SQOff                                                                  struct {
		Head, Tail, RingMask, RingEntries, Flags, Dropped, Array, Resv1 uint32
		UserAddr                                                        uint64
	}
	CQOff struct {
		Head, Tail, RingMask, RingEntries, Overflow, CQEs, Flags, Resv1 uint32
		UserAddr                                                        uint64
	}
}

// canaryUringSetup creates a one-entry ring (caller closes it).
func canaryUringSetup(p *ioUringParams) (int, error) {
	fd, _, e := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(p)), 0)
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}

// canaryUringPersonality submits one no-op request under a registered
// personality: the kernel checks those credentials with
// security_uring_override_creds at submission. A failure before the submit
// (setup, registration, the mappings, the enter call) is a
// canaryFixtureError: the hook may not have been reached. The result is the
// no-op's completion (canaryUringCompletion), where an LSM that refuses the
// credentials reports it.
func canaryUringPersonality() error {
	var p ioUringParams
	fd, err := canaryUringSetup(&p)
	if err != nil {
		return canaryFixtureError{err}
	}
	defer unix.Close(fd)
	id, _, e := unix.Syscall6(unix.SYS_IO_URING_REGISTER, uintptr(fd), ioringRegisterPersonality, 0, 0, 0, 0)
	if e != 0 {
		return canaryFixtureError{e}
	}
	ring, err := unix.Mmap(fd, 0, int(p.SQOff.Array+p.SQEntries*4), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return canaryFixtureError{err}
	}
	defer unix.Munmap(ring)
	sqes, err := unix.Mmap(fd, ioringOffSQES, int(p.SQEntries*ioringSQESize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return canaryFixtureError{err}
	}
	defer unix.Munmap(sqes)
	cq, err := unix.Mmap(fd, ioringOffCQRing, int(p.CQOff.CQEs+p.CQEntries*ioringCQESize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return canaryFixtureError{err}
	}
	defer unix.Munmap(cq)
	for i := range sqes[:ioringSQESize] {
		sqes[i] = 0
	}
	sqes[0] = ioringOpNop
	binary.LittleEndian.PutUint16(sqes[42:], uint16(id)) // personality
	tail := (*uint32)(unsafe.Pointer(&ring[p.SQOff.Tail]))
	mask := *(*uint32)(unsafe.Pointer(&ring[p.SQOff.RingMask]))
	t := atomic.LoadUint32(tail)
	*(*uint32)(unsafe.Pointer(&ring[p.SQOff.Array+(t&mask)*4])) = 0
	atomic.StoreUint32(tail, t+1)
	// Submit the one request and wait for its completion.
	n, _, e := unix.Syscall6(unix.SYS_IO_URING_ENTER, uintptr(fd), 1, 1, ioringEnterGetEvents, 0, 0)
	if e != 0 {
		return canaryFixtureError{e}
	}
	if n != 1 {
		return canaryFixtureError{unix.EAGAIN}
	}
	head := atomic.LoadUint32((*uint32)(unsafe.Pointer(&cq[p.CQOff.Head])))
	if atomic.LoadUint32((*uint32)(unsafe.Pointer(&cq[p.CQOff.Tail]))) == head {
		return canaryFixtureError{unix.EAGAIN} // no completion: unknown
	}
	cqMask := *(*uint32)(unsafe.Pointer(&cq[p.CQOff.RingMask]))
	cqe := p.CQOff.CQEs + (head&cqMask)*ioringCQESize
	return canaryUringCompletion(int32(binary.LittleEndian.Uint32(cq[cqe+8:]))) // struct io_uring_cqe.res
}

// canaryUringCompletion is a completion result as the call's result: a
// negative errno, or nil.
func canaryUringCompletion(res int32) error {
	if res < 0 {
		return syscall.Errno(-res)
	}
	return nil
}

// canaryUringAvailable sets up and closes a ring; tests replace it.
var canaryUringAvailable = func() error {
	var p ioUringParams
	return canaryClose(canaryUringSetup(&p))
}

// canaryMaxUserNamespaces is the user namespace limit; tests replace it.
var canaryMaxUserNamespaces = "/proc/sys/user/max_user_namespaces"

// canaryUnprovable returns why a hook has no harmless trigger on this node,
// or "".
func canaryUnprovable(hook string) string {
	if canaryNeverProvable[hook] {
		return "no harmless trigger: it loads a kernel module, firmware or kexec image"
	}
	switch hook {
	case "uring_override_creds":
		if err := canaryUringAvailable(); err != nil {
			return fmt.Sprintf("io_uring is not available on this node (%v)", err)
		}
	case "userns_create":
		if b, err := os.ReadFile(canaryMaxUserNamespaces); err == nil && strings.TrimSpace(string(b)) == "0" {
			return "user namespaces are disabled on this node (user.max_user_namespaces=0)"
		}
	}
	if !canaryTriggered(hook) {
		return "no canary trigger"
	}
	return ""
}
