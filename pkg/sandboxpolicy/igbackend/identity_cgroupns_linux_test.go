package igbackend

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"golang.org/x/sys/unix"
)

// The EKS failure mode: a pod-confined agent sits in a private cgroup namespace
// (containerd on cgroup v2), so the kernel renders another container's
// /proc/<pid>/cgroup relative to the agent's namespace root ("0::/../...")
// while the binding carries the host-absolute path. These tests reproduce that
// with real kernel namespaces by re-executing the test binary into a private
// cgroup namespace; PID 1 stands in for a workload in a sibling cgroup.

const cgroupnsChildEnv = "NODE_AGENT_CGROUPNS_CHILD"

// In namespaced children keep the main goroutine on the main thread: the
// runtime wedges, rather than exits, a main thread whose goroutine dies locked,
// so worker threads must never be the main thread for retirement checks.
func init() {
	if os.Getenv(cgroupnsChildEnv) != "" {
		runtime.LockOSThread()
	}
}

func unifiedCgroup(t *testing.T, file string) string {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p
		}
	}
	t.Fatalf("no unified cgroup in %s", file)
	return ""
}

// hostCgroupFixture returns PID 1's host-absolute cgroup when this process is
// in the initial cgroup namespace and PID 1 lives in a different cgroup.
func hostCgroupFixture(t *testing.T) (string, *os.File) {
	t.Helper()
	own, err := os.Open("/proc/self/ns/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = own.Close() })
	if requireInitialCgroupNamespace(own) != nil {
		t.Skip("test process is not in the initial cgroup namespace")
	}
	target := unifiedCgroup(t, "/proc/1/cgroup")
	if target == "/" || target == unifiedCgroup(t, "/proc/self/cgroup") {
		t.Skip("PID 1 must be in a non-root cgroup distinct from the test process")
	}
	return target, own
}

func runCgroupnsChild(t *testing.T, mode, target string, attr *syscall.SysProcAttr, extra ...*os.File) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), cgroupnsChildEnv+"="+mode, "NODE_AGENT_CGROUPNS_TARGET="+target)
	cmd.SysProcAttr = attr
	cmd.ExtraFiles = extra
	out, err := cmd.CombinedOutput()
	if err != nil {
		if len(out) == 0 {
			t.Skipf("cannot create namespaced child: %v", err)
		}
		t.Fatalf("namespaced child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "CGROUPNS_CHILD_OK") {
		t.Fatalf("namespaced child did not run its assertions:\n%s", out)
	}
}

func assertAgentRendersRelative(t *testing.T, target string) {
	t.Helper()
	if got := unifiedCgroup(t, "/proc/1/cgroup"); got == target || !strings.HasPrefix(got, "/..") {
		t.Fatalf("private cgroupns must render %q relative to its root, got %q", target, got)
	}
	own, err := os.Open("/proc/self/ns/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	if err := requireInitialCgroupNamespace(own); err == nil {
		t.Fatal("private cgroup namespace accepted as the host cgroup namespace")
	}
}

func pinnedProcLease(t *testing.T, target string, hostCgroup *os.File) *linuxLease {
	t.Helper()
	proc, err := os.Open("/proc/1")
	if err != nil {
		t.Fatal(err)
	}
	l := &linuxLease{proc: proc, hostCgroup: hostCgroup, identity: sandboxpolicy.Binding{CgroupPath: target}}
	if l.start, err = l.readStart(); err != nil {
		t.Fatal(err)
	}
	return l
}

// Unprivileged: a private user+cgroup namespace reproduces the EKS rendering.
// Trusting the agent's own namespace yields the observed EKS error, and a
// host pin the agent cannot enter fails closed instead of being skipped.
func TestLinuxLeaseCgroupNamespaceRenderingFailsClosed(t *testing.T) {
	if os.Getenv(cgroupnsChildEnv) == "unprivileged" {
		target := os.Getenv("NODE_AGENT_CGROUPNS_TARGET")
		assertAgentRendersRelative(t, target)
		own, err := os.Open("/proc/self/ns/cgroup")
		if err != nil {
			t.Fatal(err)
		}
		l := pinnedProcLease(t, target, own)
		if err := l.Check(); err == nil || err.Error() != "process cgroup changed" {
			t.Fatalf("agent-namespace read must reproduce the EKS rejection, got %v", err)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		// fd 3: the parent's initial cgroup namespace, owned by the initial
		// user namespace in which this child holds no capabilities.
		l = pinnedProcLease(t, target, os.NewFile(3, "host cgroup namespace"))
		if err := l.Check(); err == nil || !strings.Contains(err.Error(), "entering host cgroup namespace") {
			t.Fatalf("unenterable host cgroup namespace must fail closed, got %v", err)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		t.Log("CGROUPNS_CHILD_OK")
		return
	}
	target, own := hostCgroupFixture(t)
	runCgroupnsChild(t, "unprivileged", target, &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWCGROUP,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}, own)
}

// Privileged opt-in (root, like the hostPID node-agent with CAP_SYS_ADMIN): in a
// private cgroup namespace the full validator still binds and re-checks the
// host-absolute path through the pinned initial cgroup namespace.
func TestLinuxValidatorPrivateCgroupNamespaceKernel(t *testing.T) {
	if os.Getenv(cgroupnsChildEnv) == "privileged" {
		target := os.Getenv("NODE_AGENT_CGROUPNS_TARGET")
		assertAgentRendersRelative(t, target)
		var cg, mnt unix.Stat_t
		if err := unix.Stat(filepath.Join("/sys/fs/cgroup", target), &cg); err != nil {
			t.Fatal(err)
		}
		if err := unix.Stat("/proc/1/ns/mnt", &mnt); err != nil {
			t.Fatal(err)
		}
		binding := sandboxpolicy.Binding{Runtime: "containerd", ContainerID: strings.Repeat("a", 64), PID: 1, CgroupID: cg.Ino, CgroupPath: target, MountNamespace: mnt.Ino}
		lease, err := (LinuxValidator{}).Acquire(context.Background(), binding)
		if err != nil {
			t.Fatalf("private-cgroupns agent rejected a verified host binding: %v", err)
		}
		for range 3 {
			if err := lease.Check(); err != nil {
				t.Fatalf("recheck: %v", err)
			}
		}
		// Thread restoration: this goroutine's later reads are still namespaced.
		assertAgentRendersRelative(t, target)
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		t.Log("CGROUPNS_CHILD_OK")
		return
	}
	if os.Getenv("NODE_AGENT_CGROUPNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("root and NODE_AGENT_CGROUPNS_KERNEL_TEST=1 required")
	}
	target, _ := hostCgroupFixture(t)
	runCgroupnsChild(t, "privileged", target, &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWCGROUP})
}

// enterableSiblingCgroupNamespace creates a second cgroup namespace owned by
// this child's user namespace, leaving every thread in the original one.
func enterableSiblingCgroupNamespace(t *testing.T) (*os.File, [2]uint64) {
	t.Helper()
	type pinned struct {
		ns  *os.File
		err error
	}
	done := make(chan pinned, 1)
	go func() {
		runtime.LockOSThread()
		own, _, err := threadCgroupNamespace()
		if err != nil {
			runtime.UnlockOSThread()
			done <- pinned{err: err}
			return
		}
		defer own.Close()
		if err := unix.Unshare(unix.CLONE_NEWCGROUP); err != nil {
			runtime.UnlockOSThread()
			done <- pinned{err: err}
			return
		}
		sibling, _, err := threadCgroupNamespace()
		if restoreErr := unix.Setns(int(own.Fd()), unix.CLONE_NEWCGROUP); restoreErr != nil {
			done <- pinned{err: fmt.Errorf("fixture thread not restored: %w", restoreErr)} // stays locked: retired
			return
		}
		runtime.UnlockOSThread()
		done <- pinned{sibling, err}
	}()
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	_, current, err := threadCgroupNamespace()
	if err != nil {
		t.Fatal(err)
	}
	return r.ns, current
}

func assertThreadsIn(t *testing.T, want [2]uint64) {
	t.Helper()
	for range 4 * runtime.GOMAXPROCS(0) {
		ch := make(chan error, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ns, id, err := threadCgroupNamespace()
			if err == nil {
				err = ns.Close()
				if id != want {
					err = fmt.Errorf("thread %d is in a foreign cgroup namespace", unix.Gettid())
				}
			}
			ch <- err
		}()
		if err := <-ch; err != nil {
			t.Fatal(err)
		}
	}
}

// A failed restore must retire the worker thread (it exits still locked)
// rather than return it to the scheduler inside the host cgroup namespace.
func TestLinuxLeaseRestoreFailureRetiresThread(t *testing.T) {
	if os.Getenv(cgroupnsChildEnv) == "restore" {
		sibling, original := enterableSiblingCgroupNamespace(t)
		proc, err := os.Open("/proc/self")
		if err != nil {
			t.Fatal(err)
		}
		lease := &linuxLease{proc: proc, hostCgroup: sibling}
		defer lease.Close()
		// Control: the real restore succeeds, is verified, and leaks nothing.
		if _, err := lease.readHostCgroup(); err != nil {
			t.Fatalf("restorable switch failed: %v", err)
		}
		assertThreadsIn(t, original)

		tids := make(chan int, 1)
		previous := restoreThreadCgroupNamespace
		restoreThreadCgroupNamespace = func(int) error {
			tids <- unix.Gettid()
			return unix.EPERM
		}
		_, err = lease.readHostCgroup()
		restoreThreadCgroupNamespace = previous
		if err == nil || !strings.Contains(err.Error(), "restoring agent cgroup namespace") {
			t.Fatalf("restore failure not reported: %v", err)
		}
		tid := <-tids
		task := fmt.Sprintf("/proc/self/task/%d", tid)
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(task); os.IsNotExist(err) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("worker thread %d still alive after failed restore", tid)
			}
			time.Sleep(10 * time.Millisecond)
		}
		assertThreadsIn(t, original)
		t.Log("CGROUPNS_CHILD_OK")
		return
	}
	runCgroupnsChild(t, "restore", "", &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWCGROUP,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	})
}
