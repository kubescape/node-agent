package igbackend

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// These tests load the exact profile validateRootSeccomp accepts into a real
// kernel, unprivileged (no_new_privs), in a re-executed child of the test
// binary, and prove threads still work while namespace/root changes are
// refused. The child is root with full capabilities in its own user and mount
// namespaces, so without the filter every denied call below would succeed or
// fail with something other than EPERM; the no-filter control proves that.

const rootSeccompChildEnv = "NODE_AGENT_ROOT_SECCOMP_CHILD"

// The helper is a glibc/musl program: pthread_create uses clone3 first on
// glibc >= 2.34 and must fall back to clone(2) when clone3 returns ENOSYS.
const rootSeccompThreadHelper = `#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
static void *run(void *arg) { return arg; }
int main(void) {
	pthread_t thread;
	int rc = pthread_create(&thread, NULL, run, NULL);
	if (rc == 0) rc = pthread_join(thread, NULL);
	printf("pthread_create=%d (%s)\n", rc, strerror(rc));
	return rc == 0 ? 0 : 1;
}
`

var rootSeccompSyscalls = map[string]uint32{
	"chroot": unix.SYS_CHROOT, "pivot_root": unix.SYS_PIVOT_ROOT, "unshare": unix.SYS_UNSHARE,
	"setns": unix.SYS_SETNS, "clone3": unix.SYS_CLONE3, "clone": unix.SYS_CLONE,
}

// compileRootSeccomp lowers the canonical OCI profile shape to classic BPF.
// It handles only that shape: unconditional errno rules and single arg0
// MASKED_EQ rules whose mask fits the low 32 bits clone(2) actually reads.
func compileRootSeccomp(t *testing.T, profile *specs.LinuxSeccomp) []unix.SockFilter {
	t.Helper()
	stmt := func(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
	jump := func(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
	}
	const (
		ldAbs = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		ret   = unix.BPF_RET | unix.BPF_K
	)
	prog := []unix.SockFilter{
		stmt(ldAbs, 4), // seccomp_data.arch
		jump(jeq, unix.AUDIT_ARCH_X86_64, 1, 0),
		stmt(ret, unix.SECCOMP_RET_KILL_PROCESS),
		stmt(ldAbs, 0), // seccomp_data.nr
		jump(unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K, 0x40000000, 0, 1), // x32 ABI
		stmt(ret, unix.SECCOMP_RET_KILL_PROCESS),
	}
	for _, rule := range profile.Syscalls {
		if rule.Action != specs.ActErrno || rule.ErrnoRet == nil {
			t.Fatalf("unsupported rule %+v", rule)
		}
		deny := stmt(ret, unix.SECCOMP_RET_ERRNO|uint32(*rule.ErrnoRet))
		for _, name := range rule.Names {
			nr, ok := rootSeccompSyscalls[name]
			if !ok {
				t.Fatalf("unknown syscall %s", name)
			}
			switch len(rule.Args) {
			case 0:
				prog = append(prog, jump(jeq, nr, 0, 1), deny)
			case 1:
				arg := rule.Args[0]
				if arg.Index != 0 || arg.Op != specs.OpMaskedEqual || arg.Value != arg.ValueTwo || arg.Value>>32 != 0 {
					t.Fatalf("unsupported arg %+v", arg)
				}
				prog = append(prog,
					jump(jeq, nr, 0, 4),
					stmt(ldAbs, 16), // low 32 bits of args[0]
					stmt(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, uint32(arg.Value)),
					jump(jeq, uint32(arg.Value), 0, 1),
					deny,
					stmt(ldAbs, 0),
				)
			default:
				t.Fatalf("unsupported args %+v", rule.Args)
			}
		}
	}
	return append(prog, stmt(ret, unix.SECCOMP_RET_ALLOW))
}

func loadRootSeccomp(t *testing.T, profile *specs.LinuxSeccomp) {
	t.Helper()
	prog := compileRootSeccomp(t, profile)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		t.Fatalf("seccomp: %v", errno)
	}
}

// rawClone forks with the given flags; a child that escapes the filter exits
// at once so the assertion is made only in the parent.
func rawClone(flags uintptr) syscall.Errno {
	pid, _, errno := unix.RawSyscall6(unix.SYS_CLONE, flags|uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	if pid == 0 {
		unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
	}
	var status unix.WaitStatus
	_, _ = unix.Wait4(int(pid), &status, 0, nil)
	return 0
}

func rootSeccompChild(t *testing.T, mode string) {
	if mode == "no-filter" {
		for name, errno := range rootChangeErrnos() {
			if errno == unix.EPERM {
				t.Errorf("%s = EPERM without the filter; the check does not discriminate", name)
			}
		}
		return
	}
	profile := canonicalRootSeccomp()
	want := unix.ENOSYS
	if mode == "eperm-control" {
		eperm := uint(unix.EPERM)
		profile.Syscalls[1].ErrnoRet = &eperm
		want = unix.EPERM
	} else if err := validateRootSeccomp(profile); err != nil {
		t.Fatal(err)
	}
	loadRootSeccomp(t, profile)

	if _, _, errno := unix.RawSyscall(unix.SYS_CLONE3, 0, 0, 0); errno != want {
		t.Fatalf("clone3 = %v, want %v", errno, want)
	}
	if mode == "eperm-control" {
		// This cgo test binary creates Ms with pthread_create, so under EPERM
		// any new runtime thread aborts the process. Replace it with the libc
		// helper at once; the filter survives execve.
		helper := os.Getenv("NODE_AGENT_ROOT_SECCOMP_HELPER")
		t.Fatal(unix.Exec(helper, []string{helper}, os.Environ()))
	}
	// Go creates Ms with pthread_create (cgo) or clone(2) and plain thread
	// flags; locked, concurrently blocked goroutines need distinct OS threads.
	// A failed thread creation is fatal.
	const threads = 8
	var wg sync.WaitGroup
	tids := make(chan int, threads)
	release := make(chan struct{})
	for range threads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread() // never unlocked: the thread exits with the goroutine
			tids <- unix.Gettid()
			<-release
		}()
	}
	seen := map[int]bool{}
	for range threads {
		seen[<-tids] = true
	}
	close(release)
	wg.Wait()
	if len(seen) != threads {
		t.Fatalf("goroutines shared OS threads: %v", seen)
	}

	for name, errno := range rootChangeErrnos() {
		if errno != unix.EPERM {
			t.Errorf("%s = %v, want EPERM", name, errno)
		}
	}
	// A plain fork must still work.
	if errno := rawClone(0); errno != 0 {
		t.Errorf("clone(SIGCHLD) = %v", errno)
	}

	// The filter is inherited across execve, so the libc thread proof runs
	// under exactly this profile.
	out, err := exec.Command(os.Getenv("NODE_AGENT_ROOT_SECCOMP_HELPER")).CombinedOutput()
	if err != nil {
		t.Fatalf("pthread_create under the accepted profile failed: %v: %s", err, out)
	}
}

// rootChangeErrnos attempts every namespace/root change the barrier refuses.
func rootChangeErrnos() map[string]syscall.Errno {
	errnoOf := func(err error) syscall.Errno {
		if errno, ok := err.(syscall.Errno); ok {
			return errno
		}
		return 0
	}
	return map[string]syscall.Errno{
		"unshare(CLONE_NEWUSER)":         errnoOf(unix.Unshare(unix.CLONE_NEWUSER)),
		"unshare(CLONE_NEWNS)":           errnoOf(unix.Unshare(unix.CLONE_NEWNS)),
		"setns":                          errnoOf(unix.Setns(-1, 0)),
		"chroot":                         errnoOf(unix.Chroot("/")),
		"pivot_root":                     errnoOf(unix.PivotRoot(".", ".")),
		"clone(CLONE_NEWUSER)":           rawClone(unix.CLONE_NEWUSER),
		"clone(CLONE_NEWNS)":             rawClone(unix.CLONE_NEWNS),
		"clone(NEWUSER|NEWNS|NEWPID)":    rawClone(unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID),
		"clone(1<<32|CLONE_NEWUSER)":     rawClone(1<<32 | unix.CLONE_NEWUSER),
		"clone(CLONE_NEWNS|CLONE_FILES)": rawClone(unix.CLONE_NEWNS | unix.CLONE_FILES),
	}
}

func runRootSeccompChild(t *testing.T, mode, helper string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), rootSeccompChildEnv+"="+mode, "NODE_AGENT_ROOT_SECCOMP_HELPER="+helper)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if len(out) == 0 {
			t.Skipf("cannot create user-namespace child: %v", err)
		}
		return string(out), fmt.Errorf("seccomp child %s failed: %w", mode, err)
	}
	return string(out), nil
}

func buildRootSeccompHelper(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler for the libc thread helper")
	}
	dir := t.TempDir()
	src, bin := filepath.Join(dir, "thread.c"), filepath.Join(dir, "thread")
	if err := os.WriteFile(src, []byte(rootSeccompThreadHelper), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-O2", "-pthread", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("cannot build libc thread helper: %v: %s", err, out)
	}
	return bin
}

// libcUsesClone3 reports whether the host libc tries clone3 first for threads
// (glibc >= 2.34); only then does the EPERM control demonstrate the breakage.
func libcUsesClone3(t *testing.T) bool {
	t.Helper()
	out, err := exec.Command("getconf", "GNU_LIBC_VERSION").Output()
	if err != nil {
		return false
	}
	var major, minor int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "glibc %d.%d", &major, &minor); err != nil {
		return false
	}
	return major > 2 || (major == 2 && minor >= 34)
}

func TestRootSeccompKernelThreadsWorkAndNamespacesDenied(t *testing.T) {
	if mode := os.Getenv(rootSeccompChildEnv); mode != "" {
		rootSeccompChild(t, mode)
		return
	}
	helper := buildRootSeccompHelper(t)
	for _, mode := range []string{"no-filter", "enosys"} {
		if out, err := runRootSeccompChild(t, mode, helper); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	}
}

// Control: the previous contract (clone3 -> EPERM) still blocks namespaces
// but breaks libc thread creation, which is why ENOSYS is required.
func TestRootSeccompKernelEPERMClone3BreaksThreads(t *testing.T) {
	if mode := os.Getenv(rootSeccompChildEnv); mode != "" {
		rootSeccompChild(t, mode)
		return
	}
	helper := buildRootSeccompHelper(t)
	out, err := runRootSeccompChild(t, "eperm-control", helper)
	if !libcUsesClone3(t) {
		t.Skip("host libc does not use clone3 for threads")
	}
	if err == nil || !strings.Contains(out, fmt.Sprintf("pthread_create=%d ", unix.EPERM)) {
		t.Fatalf("expected pthread_create to fail with EPERM under clone3 -> EPERM: %v\n%s", err, out)
	}
}
