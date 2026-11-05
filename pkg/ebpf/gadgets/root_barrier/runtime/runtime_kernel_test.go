//go:build linux && root_barrier_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

// Opt-in test of the root barrier with Inspektor Gadget alone. It starts a
// disposable Docker container with CAP_SYS_ADMIN and CAP_SYS_CHROOT and
// without seccomp or AppArmor, so that only the barrier can deny. Requires
// root, BPF LSM, Docker and an image with Python 3.12+ (glibc 2.34+):
//
//	ROOT_BARRIER_KERNEL_TEST=1
//	ROOT_BARRIER_IMAGE_ARCHIVE   OCI archive from `ig image export`
//	ROOT_BARRIER_IMAGE           image name in the archive
//	ROOT_BARRIER_DISABLED_IMAGE  optional: an image of the gadget built with
//	                             programs.rb_chroot.attach_to set to
//	                             gadget_program_disabled, in the same archive
//	ROOT_BARRIER_PYTHON_IMAGE    container image, default python:3.13-slim

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"golang.org/x/sys/unix"
	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/rootbarrier"
)

// agent runs as the container's first process, so it exists before the
// gadget starts. For each /tmp/go-<n> it runs the operations and writes the
// results to /tmp/res-<n>.
const agent = `
import ctypes, os, threading, time
libc = ctypes.CDLL(None, use_errno=True)
def op(f):
    try:
        f(); return "ok"
    except OSError as e:
        return os.strerror(e.errno)
def thread():
    t = threading.Thread(target=lambda: None); t.start(); t.join()
n = 0
while True:
    n += 1
    while not os.path.exists("/tmp/go-%d" % n):
        time.sleep(0.05)
    r = ["thread=" + op(thread), "chroot=" + op(lambda: os.chroot("/")),
         "unshare=" + op(lambda: os.unshare(os.CLONE_NEWNS))]
    open("/tmp/res.tmp", "w").write(" ".join(r))
    os.rename("/tmp/res.tmp", "/tmp/res-%d" % n)
`

// clone3NS calls clone3 with CLONE_NEWNS; the child exits at once.
const clone3NS = `
import ctypes, os, struct
libc = ctypes.CDLL(None, use_errno=True)
args = ctypes.create_string_buffer(struct.pack("<11Q", 0x20000, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0), 88)
pid = libc.syscall(435, args, 88)
if pid == 0:
    os._exit(0)
if pid < 0:
    raise SystemExit("clone3: " + os.strerror(ctypes.get_errno()))
os.waitpid(pid, 0)
`

// pyMount calls mount(2) for a new tmpfs.
const pyMount = `
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(b"none", b"/mnt", b"tmpfs", 0, None) != 0:
    raise SystemExit("mount: " + os.strerror(ctypes.get_errno()))
`

// pyMoveMount moves the existing /dev/mqueue mount to /mnt: open_tree without
// OPEN_TREE_CLONE needs no capability, so only move_mount is judged.
const pyMoveMount = `
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.syscall(428, -100, b"/dev/mqueue", 0)
if fd < 0:
    raise SystemExit("open_tree: " + os.strerror(ctypes.get_errno()))
if libc.syscall(429, fd, b"", -100, b"/mnt", 4) != 0:
    raise SystemExit("move_mount: " + os.strerror(ctypes.get_errno()))
`

// pyOpenTreeClone clones the /dev/mqueue mount (OPEN_TREE_CLONE).
const pyOpenTreeClone = `
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
if libc.syscall(428, -100, b"/dev/mqueue", 1) < 0:
    raise SystemExit("open_tree: " + os.strerror(ctypes.get_errno()))
`

type fixture struct {
	t       *testing.T
	ctx     context.Context
	manager *instancemanager.Manager
	store   *orasoci.ReadOnlyStore
	handler operators.DataOperator
	id      string
	cgroup  uint64
	exempt  uint64
	goes    int
}

func (f *fixture) docker(args ...string) (string, error) {
	out, err := exec.CommandContext(f.ctx, "docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (f *fixture) exec(args ...string) error {
	out, err := f.docker(append([]string{"exec", f.id}, args...)...)
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// trigger asks the agent to run its operations once and returns the results.
func (f *fixture) trigger() string {
	f.goes++
	if err := f.exec("touch", fmt.Sprintf("/tmp/go-%d", f.goes)); err != nil {
		f.t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if out, err := f.docker("exec", f.id, "cat", fmt.Sprintf("/tmp/res-%d", f.goes)); err == nil {
			return out
		}
		time.Sleep(100 * time.Millisecond)
	}
	f.t.Fatal("agent did not answer")
	return ""
}

// start starts one gadget instance and returns its owner.
func (f *fixture) start(id, image string, config Config) (*Owner, error) {
	var owner *Owner
	capture := simple.New("root-barrier-test-"+id, simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		var err error
		owner, err = GetOwner(gc)
		return err
	}))
	desired := &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: image}}
	err := f.manager.StartGadget(f.ctx, desired, gadgetcontext.WithOrasReadonlyTarget(f.store),
		gadgetcontext.WithAdditionalDataOperators(f.handler, New(), capture), WithConfig(config))
	return owner, err
}

func (f *fixture) stop(id string) {
	if err := f.manager.StopGadget(context.Background(), id); err != nil {
		f.t.Logf("stopping %s: %v", id, err)
	}
}

// denied runs a command in the container and checks that it fails and that
// the barrier counted the operation.
func (f *fixture) denied(owner *Owner, op rootbarrier.Op, args ...string) {
	f.t.Helper()
	before, err := owner.Denials()
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.exec(args...); err == nil {
		f.t.Errorf("%v: allowed in a covered container", args)
		return
	}
	after, err := owner.Denials()
	if err != nil {
		f.t.Fatal(err)
	}
	if after[op] == before[op] {
		f.t.Errorf("%v: failed, but the barrier did not count %s", args, op)
	}
}

func TestRootBarrierWithInspektorGadgetAlone(t *testing.T) {
	if os.Getenv("ROOT_BARRIER_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	f := &fixture{t: t, ctx: ctx}

	python := os.Getenv("ROOT_BARRIER_PYTHON_IMAGE")
	if python == "" {
		python = "python:3.13-slim"
	}
	var err error
	f.id, err = f.docker("run", "-d", "--rm", "--cap-add", "SYS_ADMIN", "--cap-add", "SYS_CHROOT",
		"--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined",
		python, "python3", "-c", agent)
	if err != nil {
		t.Fatalf("starting container: %v: %s", err, f.id)
	}
	defer f.docker("rm", "-f", f.id)
	pid, err := f.docker("inspect", "-f", "{{.State.Pid}}", f.id)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("/proc", pid, "cgroup"))
	if err != nil {
		t.Fatal(err)
	}
	cgroupPath := strings.TrimPrefix(strings.TrimSpace(string(data)), "0::")
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", cgroupPath), &st); err != nil {
		t.Fatal(err)
	}
	f.cgroup = st.Ino
	// docker exec runs runc init in the cgroup before it joins the container:
	// leave the runtime's mount namespace uncovered.
	if f.exempt, err = enforcement.RuntimeMountNamespace(); err != nil {
		t.Fatal(err)
	}

	if f.store, err = orasoci.NewFromTar(ctx, os.Getenv("ROOT_BARRIER_IMAGE_ARCHIVE")); err != nil {
		t.Fatal(err)
	}
	rt := local.New()
	if err := rt.Init(nil); err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if f.manager, err = instancemanager.New(rt); err != nil {
		t.Fatal(err)
	}
	handler := ocihandler.New()
	params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	if err := params.Set("allow-enforcement", "true"); err != nil {
		t.Fatal(err)
	}
	if err := handler.Init(params); err != nil {
		t.Fatal(err)
	}
	f.handler = handler
	image := os.Getenv("ROOT_BARRIER_IMAGE")
	covered := Cgroup{ID: f.cgroup, ExemptMntns: f.exempt}

	t.Run("uncovered container is not judged", func(t *testing.T) {
		if err := f.exec("unshare", "-m", "true"); err != nil {
			t.Fatalf("unshare before the gadget: %v", err)
		}
		if res := f.trigger(); res != "thread=ok chroot=ok unshare=ok" {
			t.Fatalf("agent before the gadget: %s", res)
		}
	})

	if disabled := os.Getenv("ROOT_BARRIER_DISABLED_IMAGE"); disabled != "" {
		t.Run("startup with a missing hook is refused", func(t *testing.T) {
			_, err := f.start("root-barrier-disabled", disabled, Config{Initial: []Cgroup{covered}})
			defer f.stop("root-barrier-disabled")
			if err == nil || !strings.Contains(err.Error(), "rb_chroot->path_chroot") {
				t.Fatalf("startup without the chroot hook: %v", err)
			}
			// Its other programs must be gone after the refusal.
			if err := f.exec("unshare", "-m", "true"); err != nil {
				t.Fatalf("a refused instance must not stay: %v", err)
			}
		})
	}

	a, err := f.start("root-barrier-a", image, Config{})
	if err != nil {
		t.Fatalf("starting instance a: %v", err)
	}
	defer f.stop("root-barrier-a")
	if err := a.Cover(covered); err != nil {
		t.Fatal(err)
	}

	t.Run("denied root and namespace changes", func(t *testing.T) {
		f.denied(a, rootbarrier.OpChroot, "chroot", "/", "true")
		f.denied(a, rootbarrier.OpPivotRoot, "pivot_root", "/", "/")
		f.denied(a, rootbarrier.OpUnshareNS, "unshare", "-m", "true")
		f.denied(a, rootbarrier.OpUserns, "unshare", "-U", "true")
		f.denied(a, rootbarrier.OpSetns, "nsenter", "-t", "1", "-m", "true")
		f.denied(a, rootbarrier.OpSetns, "python3", "-c", "import os\nos.setns(os.open('/proc/1/ns/mnt', os.O_RDONLY), 0)")
		f.denied(a, rootbarrier.OpNewMount, "python3", "-c", pyOpenTreeClone)
		f.denied(a, rootbarrier.OpCloneNS, "python3", "-c", clone3NS)
		f.denied(a, rootbarrier.OpMount, "python3", "-c", pyMount)
		f.denied(a, rootbarrier.OpMoveMount, "python3", "-c", pyMoveMount)
		f.denied(a, rootbarrier.OpUmount, "umount", "/proc/kcore")
		// util-linux 2.39+ mounts with fsopen, fsconfig, fsmount and move_mount.
		f.denied(a, rootbarrier.OpNewMount, "mount", "-t", "tmpfs", "none", "/mnt")
	})

	t.Run("joining other namespace types still works", func(t *testing.T) {
		// docker exec itself joins the cgroup namespace inside the cgroup.
		if err := f.exec("nsenter", "-t", "1", "-C", "true"); err != nil {
			t.Fatalf("setns into a cgroup namespace: %v", err)
		}
	})

	t.Run("glibc threads still work", func(t *testing.T) {
		if err := f.exec("python3", "-c", "import threading\nfor _ in range(50):\n t=threading.Thread(target=lambda:None); t.start(); t.join()"); err != nil {
			t.Fatalf("threads in a covered container: %v", err)
		}
	})

	t.Run("already running task is covered", func(t *testing.T) {
		if res := f.trigger(); res != "thread=ok chroot=Operation not permitted unshare=Operation not permitted" {
			t.Fatalf("agent started before the gadget: %s", res)
		}
	})

	t.Run("a task in a child cgroup stays covered", func(t *testing.T) {
		sub := filepath.Join("/sys/fs/cgroup", cgroupPath, "rb-sub")
		if err := os.Mkdir(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(sub)
		move := func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(pid), 0); err != nil {
				t.Fatal(err)
			}
		}
		move(sub)
		defer move(filepath.Join("/sys/fs/cgroup", cgroupPath))
		if res := f.trigger(); res != "thread=ok chroot=Operation not permitted unshare=Operation not permitted" {
			t.Fatalf("agent in a child cgroup: %s", res)
		}
	})

	t.Run("reload keeps the barrier", func(t *testing.T) {
		// A loop tries unshare during the whole switch; every success is a gap.
		if err := f.exec("sh", "-c", "rm -f /tmp/leak /tmp/stop; (while [ ! -e /tmp/stop ]; do unshare -m true && echo gap >> /tmp/leak; chroot / true && echo gap >> /tmp/leak; done) >/dev/null 2>&1 &"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		b, err := f.start("root-barrier-b", image, Config{Initial: []Cgroup{covered}})
		if err != nil {
			t.Fatalf("starting instance b: %v", err)
		}
		defer f.stop("root-barrier-b")
		f.stop("root-barrier-a")
		time.Sleep(time.Second)
		if err := f.exec("touch", "/tmp/stop"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		if out, err := f.docker("exec", f.id, "cat", "/tmp/leak"); err == nil {
			t.Fatalf("root changes passed during the reload: %q", out)
		}
		f.denied(b, rootbarrier.OpChroot, "chroot", "/", "true")
		f.stop("root-barrier-b")
		if err := f.exec("unshare", "-m", "true"); err != nil {
			t.Fatalf("after the last instance stopped: %v", err)
		}
	})

	t.Run("an earlier BPF LSM denial is kept", func(t *testing.T) {
		// The kernel runs the BPF LSM programs of a hook newest first, so a
		// program attached after the barrier runs before it. That program
		// denies chroot with EACCES in the container cgroup; the barrier must
		// keep that verdict, not replace it with EPERM.
		c, err := f.start("root-barrier-c", image, Config{Initial: []Cgroup{covered}})
		if err != nil {
			t.Fatalf("starting instance c: %v", err)
		}
		defer f.stop("root-barrier-c")
		earlier := earlierChrootDenial(t, f.cgroup)
		defer earlier.Close()
		err = f.exec("chroot", "/", "true")
		if err == nil || !strings.Contains(err.Error(), "Permission denied") {
			t.Fatalf("chroot after an earlier EACCES denial: %v", err)
		}
		// The barrier still judges the hooks the earlier program allows.
		f.denied(c, rootbarrier.OpUnshareNS, "unshare", "-m", "true")
	})
}

// earlierChrootDenial attaches a BPF LSM program on path_chroot that returns
// -EACCES for tasks in the cgroup cgroupID, and 0 for every other task.
func earlierChrootDenial(t *testing.T, cgroupID uint64) link.Link {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:       "rb_test_earlier",
		Type:       ebpf.LSM,
		AttachType: ebpf.AttachLSMMac,
		AttachTo:   "path_chroot",
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.FnGetCurrentCgroupId.Call(),
			asm.LoadImm(asm.R1, int64(cgroupID), asm.DWord),
			asm.JNE.Reg(asm.R0, asm.R1, "allow"),
			asm.Mov.Imm(asm.R0, -int32(unix.EACCES)),
			asm.Return(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("allow"),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatalf("loading the earlier LSM program: %v", err)
	}
	defer prog.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		t.Fatalf("attaching the earlier LSM program: %v", err)
	}
	return l
}
