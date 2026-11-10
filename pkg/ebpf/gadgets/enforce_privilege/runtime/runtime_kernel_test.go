//go:build linux && privilege_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

// Opt-in test of the gadget with Inspektor Gadget alone: it parses the example
// policy file, starts the gadget from an OCI archive and binds one Docker
// container through this package's operator. Requires root, BPF LSM and a
// disposable container started with seccomp=unconfined and --cap-add SYS_ADMIN:
//
//	PRIVILEGE_KERNEL_TEST=1
//	PRIVILEGE_IMAGE_ARCHIVE  OCI archive from `ig image export`
//	PRIVILEGE_IMAGE          image name in the archive
//	PRIVILEGE_CONTAINER_ID   full Docker container ID
//	PRIVILEGE_CGROUP_PATH    its cgroup v2 path under /sys/fs/cgroup, with a leading "/" (as in /proc/<pid>/cgroup)
//
// TestForkMarkFaultInjection uses the same fixture. The container needs a
// POSIX sh. TestEarlierBPFDenyHolds loads a BPF LSM program that denies every
// chroot on the node for a few seconds.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
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
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
)

// kernelFixture runs one gadget instance on the fixture container.
type kernelFixture struct {
	ctx       context.Context
	id        string
	container ContainerIdentity
	bindings  *enforcement.Bindings
	verdicts  atomic.Int32
	mu        sync.Mutex
	events    []string // hook, syscall, capability, mode and comm of each verdict
	// stop stops the last started instance.
	stop func()
}

func newKernelFixture(t *testing.T) *kernelFixture {
	t.Helper()
	if os.Getenv("PRIVILEGE_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	cleanPins(t)
	id, cgroupPath := os.Getenv("PRIVILEGE_CONTAINER_ID"), os.Getenv("PRIVILEGE_CGROUP_PATH")
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", cgroupPath), &st); err != nil {
		t.Fatal(err)
	}
	return &kernelFixture{ctx: ctx, id: id, container: ContainerIdentity{Runtime: "docker", ID: id, CgroupID: st.Ino, CgroupPath: cgroupPath}}
}

// cleanPins gives the test empty state: every load of the gadget re-opens the
// section's pinned maps (../../common/pin.h).
func cleanPins(t *testing.T) {
	t.Helper()
	if err := enforcement.RemovePinnedMaps(mapPrefix); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { enforcement.RemovePinnedMaps(mapPrefix) })
}

// start runs the gadget with the compiled documents and extra ebpf params.
func (f *kernelFixture) start(t *testing.T, name string, compiled privpolicy.Compiled, extra map[string]string) {
	t.Helper()
	store, err := orasoci.NewFromTar(f.ctx, os.Getenv("PRIVILEGE_IMAGE_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	rt := local.New()
	if err := rt.Init(nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.Close() })
	manager, err := instancemanager.New(rt)
	if err != nil {
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
	events := simple.New("privilege-test-verdicts", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		var err error
		if f.bindings, err = GetBindings(gc); err != nil {
			return err
		}
		ds := gc.GetDataSources()["verdict"]
		fields := map[string]datasource.FieldAccessor{}
		for _, name := range []string{"hook", "syscall", "capability", "mode", "comm"} {
			fields[name] = ds.GetField(name)
		}
		return ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
			hook, _ := fields["hook"].String(data)
			syscall, _ := fields["syscall"].String(data)
			capability, _ := fields["capability"].Int32(data)
			mode, _ := fields["mode"].Uint32(data)
			comm, _ := fields["comm"].String(data)
			f.mu.Lock()
			f.events = append(f.events, fmt.Sprintf("%s %s cap=%d mode=%d %s", hook, syscall, capability, mode, comm))
			f.mu.Unlock()
			f.verdicts.Add(1)
			return nil
		}, 100)
	}))
	runtimeMntns, err := enforcement.RuntimeMountNamespace()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"operator.oci.ebpf.host-mntns-id": strconv.FormatUint(runtimeMntns, 10)}
	for k, v := range extra {
		values["operator.oci.ebpf."+k] = v
	}
	desired := &api.GadgetInstance{Id: name, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: os.Getenv("PRIVILEGE_IMAGE"), ParamValues: values}}
	if err := manager.StartGadget(f.ctx, desired, gadgetcontext.WithOrasReadonlyTarget(store),
		gadgetcontext.WithAdditionalDataOperators(handler, New(), events),
		WithConfig(Config{Policy: compiled})); err != nil {
		t.Fatal(err)
	}
	f.stop = func() { manager.StopGadget(context.Background(), desired.Id) }
	t.Cleanup(f.stop)
}

func (f *kernelFixture) exec(args ...string) error {
	return exec.CommandContext(f.ctx, "docker", append([]string{"exec", f.id}, args...)...).Run()
}

func TestGadgetWithInspektorGadgetAlone(t *testing.T) {
	f := newKernelFixture(t)
	file, err := os.Open("../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := privpolicy.Parse(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, "privilege-kernel-test", compiled, nil)

	unshare := func() error { return f.exec("unshare", "-m", "true") }
	if err := unshare(); err != nil {
		t.Fatalf("unbound container must not be judged: %v", err)
	}
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatal(err)
	}
	if unshare() == nil {
		t.Fatal("the example policy denies unshare(CLONE_NEWNS) in a bound container")
	}
	if err := f.bindings.Unbind(f.container); err != nil {
		t.Fatal(err)
	}
	if err := unshare(); err != nil {
		t.Fatalf("unbound again must be allowed: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if f.verdicts.Load() == 0 {
		t.Fatal("no verdict event for the deny")
	}
}

// TestForkMarkFaultInjection makes every child arming mark fail at fork. An
// armed shell that forks must then be refused in enforce mode, with a tracking
// fault for the slot, and allowed in audit mode, with no tracking fault.
func TestForkMarkFaultInjection(t *testing.T) {
	for _, mode := range []string{"enforce", "audit"} {
		t.Run(mode, func(t *testing.T) {
			f := newKernelFixture(t)
			// One deny rule, so the slot enforces in enforce mode.
			rule := privpolicy.Rule{Name: "no-modules", Action: "deny", Target: privpolicy.Target{Syscall: []string{"init_module"}}}
			doc := privpolicy.Document{Version: 1, Name: "fault-" + mode, Policy: privpolicy.Policy{Mode: mode, Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
			compiled, err := privpolicy.CompileKernel(doc, 1)
			if err != nil {
				t.Fatal(err)
			}
			f.start(t, "privilege-fault-"+mode, compiled, map[string]string{"arming-fail-fork-marks": "true"})
			fork := func() error { return f.exec("sh", "-c", "true & wait") }
			if err := fork(); err != nil {
				t.Fatalf("an unbound container must not be judged: %v", err)
			}
			if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
				t.Fatal(err)
			}
			defer f.bindings.Unbind(f.container)
			err = fork()
			faults, ferr := f.bindings.SlotFaults(0)
			if ferr != nil {
				t.Fatal(ferr)
			}
			switch mode {
			case "enforce":
				if err == nil {
					t.Fatal("a fork whose child cannot be armed must be refused")
				}
				if faults == 0 {
					t.Fatal("the refused fork must count a tracking fault")
				}
				if !f.waitFaultVerdict(2) {
					t.Fatalf("the refused fork must send an enforce fault verdict: %v", f.events)
				}
			case "audit":
				if err != nil {
					t.Fatalf("audit mode must allow the fork: %v", err)
				}
				if faults != 0 {
					t.Fatalf("audit faults must not block: %d", faults)
				}
				time.Sleep(500 * time.Millisecond)
				if n := f.faultVerdicts(1) + f.faultVerdicts(2); n != 0 {
					t.Fatalf("a lost Audit mark sends no fault verdict: %v", f.events)
				}
				// A plain fork keeps the child in the Audit cgroup: no
				// node fault (only CLONE_INTO_CGROUP counts one).
				if w, err := f.bindings.ArmingWitness(); err != nil || w.NodeFaults != 0 {
					t.Fatalf("node faults: %+v %v", w, err)
				}
			}
		})
	}
}

// TestMissingSlotPolicyFailsClosed makes every slot miss its policy header. A
// bound cgroup with no policy is a structural fault: a Strict binding must deny
// every judged check and count a slot fault, and an Audit binding must allow
// and count no slot fault.
func TestMissingSlotPolicyFailsClosed(t *testing.T) {
	for _, mode := range []string{"enforce", "audit"} {
		t.Run(mode, func(t *testing.T) {
			f := newKernelFixture(t)
			// The policy allows unshare; only the missing header can deny it.
			rule := privpolicy.Rule{Name: "no-modules", Action: "deny", Target: privpolicy.Target{Syscall: []string{"init_module"}}}
			doc := privpolicy.Document{Version: 1, Name: "headers-" + mode, Policy: privpolicy.Policy{Mode: mode, Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
			compiled, err := privpolicy.CompileKernel(doc, 1)
			if err != nil {
				t.Fatal(err)
			}
			f.start(t, "privilege-headers-"+mode, compiled, map[string]string{"policy-fail-headers": "true"})
			unshare := func() error { return f.exec("unshare", "-m", "true") }
			if err := unshare(); err != nil {
				t.Fatalf("an unbound container must not be judged: %v", err)
			}
			if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
				t.Fatal(err)
			}
			defer f.bindings.Unbind(f.container)
			err = unshare()
			faults, ferr := f.bindings.SlotFaults(0)
			if ferr != nil {
				t.Fatal(ferr)
			}
			switch mode {
			case "enforce":
				if err == nil {
					t.Fatal("a Strict binding with no slot policy must deny")
				}
				if faults == 0 {
					t.Fatal("the structural fault must count a slot fault")
				}
				if !f.waitFaultVerdict(2) {
					t.Fatalf("the denied fault must send an enforce fault verdict: %v", f.events)
				}
			case "audit":
				if err != nil {
					t.Fatalf("an Audit binding must allow even on a fault: %v", err)
				}
				if faults != 0 {
					t.Fatalf("audit faults must not count as slot faults: %d", faults)
				}
				if !f.waitFaultVerdict(1) {
					t.Fatalf("the allowed fault must send an audit fault verdict: %v", f.events)
				}
			}
		})
	}
}

// TestChildCgroupOfStrictBindingFailsClosed moves a task of a Strict exact
// binding into a child cgroup of the container. The binding does not cover
// the child cgroup (exact scope), but the task must not run unjudged: every
// judged check is denied as a structural fault.
func TestChildCgroupOfStrictBindingFailsClosed(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-modules", Action: "deny", Target: privpolicy.Target{Syscall: []string{"init_module"}}}
	doc := privpolicy.Document{Version: 1, Name: "moved", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, "privilege-moved", compiled, nil)
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatal(err)
	}
	defer f.bindings.Unbind(f.container)
	if err := f.exec("unshare", "-m", "true"); err != nil {
		t.Fatalf("the policy allows unshare in the bound cgroup: %v", err)
	}
	parent := filepath.Join("/sys/fs/cgroup", f.container.CgroupPath)
	child := filepath.Join(parent, "moved")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(child)
	cmd := exec.CommandContext(f.ctx, "docker", "exec", f.id, "sh", "-c", "sleep 2; unshare -m true; echo rc=$?")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Move the shell into the child cgroup while it sleeps.
	moved := false
	for deadline := time.Now().Add(1500 * time.Millisecond); !moved && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		procs, _ := os.ReadFile(filepath.Join(parent, "cgroup.procs"))
		for _, pid := range strings.Fields(string(procs)) {
			cmdline, _ := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
			if strings.Contains(string(cmdline), "unshare -m true; echo") && os.WriteFile(filepath.Join(child, "cgroup.procs"), []byte(pid), 0o644) == nil {
				moved = true
				break
			}
		}
	}
	if !moved {
		t.Fatal("could not move the shell into the child cgroup")
	}
	cmd.Wait()
	if !strings.Contains(out.String(), "rc=1") {
		t.Fatalf("unshare in a child cgroup of a Strict exact binding must be denied: %q", out.String())
	}
	if faults, err := f.bindings.SlotFaults(0); err != nil || faults == 0 {
		t.Fatalf("the task outside the exact scope must count a slot fault: %d %v", faults, err)
	}
}

// TestEarlierBPFDenyHolds checks that the gadget never turns another BPF LSM
// program's deny into an allow, in both attach orders. The kernel runs the
// programs of a hook newest first and stops at the first nonzero return. The
// other program denies chroot with EACCES; the gadget would deny with EPERM,
// so the errno shows which program decided.
func TestEarlierBPFDenyHolds(t *testing.T) {
	f := newKernelFixture(t)
	chroot := func() string {
		out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, "chroot", "/", "true").CombinedOutput()
		switch {
		case err == nil:
			return "ok"
		case strings.Contains(string(out), "Permission denied"):
			return "EACCES"
		case strings.Contains(string(out), "Operation not permitted"):
			return "EPERM"
		}
		return string(out)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: "path_chroot", License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -13), asm.Return()}, // -EACCES
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	attach := func() link.Link {
		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	if got := chroot(); got != "ok" {
		t.Fatalf("baseline chroot: %s", got)
	}
	older := attach()
	defer older.Close()
	if got := chroot(); got != "EACCES" {
		t.Fatalf("the other program must deny chroot: %s", got)
	}
	rule := privpolicy.Rule{Name: "chroot-ok", Action: "allow", Target: privpolicy.Target{Syscall: []string{"chroot"}}}
	doc := privpolicy.Document{Version: 1, Name: "allow-chroot", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "deny", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, "privilege-earlier-deny", compiled, nil)
	if got := chroot(); got != "EACCES" {
		t.Fatalf("unbound, gadget newer: %s", got)
	}
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatal(err)
	}
	defer f.bindings.Unbind(f.container)
	// The gadget runs first and allows; the older program still denies.
	if got := chroot(); got != "EACCES" {
		t.Fatalf("bound with an allow rule, gadget newer: %s", got)
	}
	older.Close()
	if got := chroot(); got != "ok" {
		t.Fatalf("the gadget alone allows chroot: %s", got)
	}
	// The other program is now newer: it runs first and denies, and the
	// gadget's allow does not replace that.
	newer := attach()
	defer newer.Close()
	if got := chroot(); got != "EACCES" {
		t.Fatalf("bound with an allow rule, other program newer: %s", got)
	}
}

// standInTaskAlloc loads a BPF LSM task_alloc program that stands in for
// another enforcement gadget on the same hook (enforce_exec owns task_alloc in
// its shared collection). It returns errno (0 or a negative errno) for forks
// by a task named "sh" in the cgroup cgid, and 0 elsewhere (so runc init's own
// clones pass), and ignores the previous verdict.
func standInTaskAlloc(t *testing.T, cgid uint64, errno int32) *ebpf.Program {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: "task_alloc", License: "GPL",
		Instructions: asm.Instructions{
			asm.FnGetCurrentCgroupId.Call(),
			asm.LoadImm(asm.R1, int64(cgid), asm.DWord),
			asm.JNE.Reg(asm.R0, asm.R1, "other"),
			// comm into the stack; "sh\0\0" is 0x6873 as a little-endian word.
			asm.Mov.Reg(asm.R1, asm.R10),
			asm.Add.Imm(asm.R1, -16),
			asm.Mov.Imm(asm.R2, 16),
			asm.FnGetCurrentComm.Call(),
			asm.LoadMem(asm.R1, asm.R10, -16, asm.Word),
			asm.JNE.Imm(asm.R1, 0x6873, "other"),
			asm.Mov.Imm(asm.R0, errno),
			asm.Return(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("other"),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { prog.Close() })
	return prog
}

// TestTaskAllocCoexistence needs a busybox (or alpine) sh in the fixture
// container: its fork errors name the errno. It attaches a second BPF LSM program on task_alloc, in
// both attach orders, next to the gadget with every child mark failing:
//   - an Audit binding never denies a fork, even on that tracking fault;
//   - the other program's fork deny is never overridden: in Audit the fork
//     fails with its errno; in Strict it fails with the errno of the program
//     that runs first (the kernel runs the newest link first and stops at the
//     first nonzero return): EACCES when the other program is newer, ENOMEM
//     (the gadget's lost child) when it is older.
//
// The stand-in has no task state. The state check that Matthias's review asks
// for (a privilege deny before and after enforce_exec allocates its lineage
// state, with reclaim in task_free) needs enforce_exec itself on the same node.
func TestTaskAllocCoexistence(t *testing.T) {
	for _, order := range []string{"other-older", "other-newer"} {
		for _, mode := range []string{"enforce", "audit"} {
			t.Run(order+"/"+mode, func(t *testing.T) {
				f := newKernelFixture(t)
				fork := func() string {
					out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, "sh", "-c", "true & wait").CombinedOutput()
					switch {
					case err == nil:
						return "ok"
					case strings.Contains(string(out), "Permission denied"):
						return "EACCES"
					case strings.Contains(string(out), "Out of memory"), strings.Contains(string(out), "Cannot allocate memory"):
						return "ENOMEM"
					}
					return "failed: " + strings.TrimSpace(string(out))
				}
				attach := func(prog *ebpf.Program) link.Link {
					l, err := link.AttachLSM(link.LSMOptions{Program: prog})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { l.Close() })
					return l
				}
				allow, deny := standInTaskAlloc(t, f.container.CgroupID, 0), standInTaskAlloc(t, f.container.CgroupID, -13)
				var other link.Link
				if order == "other-older" {
					other = attach(allow)
				}
				rule := privpolicy.Rule{Name: "no-modules", Action: "deny", Target: privpolicy.Target{Syscall: []string{"init_module"}}}
				doc := privpolicy.Document{Version: 1, Name: "coexist-" + mode, Policy: privpolicy.Policy{Mode: mode, Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
				compiled, err := privpolicy.CompileKernel(doc, 1)
				if err != nil {
					t.Fatal(err)
				}
				f.start(t, "privilege-coexist", compiled, map[string]string{"arming-fail-fork-marks": "true"})
				if order == "other-newer" {
					other = attach(allow)
				}
				if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
					t.Fatal(err)
				}

				got := fork()
				if mode == "audit" && got != "ok" {
					t.Fatalf("an Audit binding must never deny a fork: %s", got)
				}
				if mode == "enforce" && got != "ENOMEM" {
					t.Fatalf("a Strict binding must refuse a fork whose child cannot be armed: %s", got)
				}

				// Replace the allowing program with a denying one, in the
				// same attach order.
				other.Close()
				if order == "other-older" {
					// Older than the gadget: attach a new gadget after it.
					f.bindings.Unbind(f.container)
					attach(deny)
					f.start(t, "privilege-coexist-2", compiled, map[string]string{"arming-fail-fork-marks": "true"})
					if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
						t.Fatal(err)
					}
				} else {
					attach(deny)
				}
				got = fork()
				switch mode {
				case "audit":
					if got != "EACCES" {
						t.Fatalf("the other program's deny must hold next to an Audit binding: %s", got)
					}
				case "enforce":
					want := "EACCES"
					if order == "other-older" {
						want = "ENOMEM"
					}
					if got != want {
						t.Fatalf("the newest program decides and no deny becomes an allow: got %s, want %s", got, want)
					}
				}
				f.bindings.Unbind(f.container)
			})
		}
	}
}

// hookFixture is a runc bundle whose OCI hooks run chroot, and a parent cgroup
// (the cgroup of a group of containers) that is bound before the container
// starts, with a policy that denies chroot.
type hookFixture struct {
	*kernelFixture
	bundle, parent, id string
	run                func(string, ...string) (string, error)
}

// newHookFixture needs runc, PRIVILEGE_ROOTFS (a rootfs folder with busybox sh
// and chroot; it is copied) and util-linux nsenter on the host. extra are ebpf
// gadget params. scope sets the Subtree and RuntimeHelpers flags of the parent
// cgroup's binding.
func newHookFixture(t *testing.T, extra map[string]string, scope enforcement.Binding) *hookFixture {
	t.Helper()
	if os.Getenv("PRIVILEGE_KERNEL_TEST") != "1" || os.Getenv("PRIVILEGE_ROOTFS") == "" {
		t.Skip("explicit disposable kernel fixture opt-in and PRIVILEGE_ROOTFS required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	cleanPins(t)
	h := &hookFixture{kernelFixture: &kernelFixture{ctx: ctx}, bundle: t.TempDir(), id: fmt.Sprintf("privilege-hooks-%d", os.Getpid())}
	h.run = func(name string, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}

	// The parent cgroup, bound before the container exists (it is empty, so
	// binding it arms no task).
	h.parent = fmt.Sprintf("/privilege-hooks-test-%d", os.Getpid())
	if err := os.Mkdir(filepath.Join("/sys/fs/cgroup", h.parent), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(filepath.Join("/sys/fs/cgroup", h.parent)) })
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", h.parent), &st); err != nil {
		t.Fatal(err)
	}
	parentID := ContainerIdentity{Runtime: "test-parent", ID: "hooks", CgroupID: st.Ino, CgroupPath: h.parent}

	// The bundle: hooks and workload all try chroot. The hooks run chroot
	// as a child of their shell, so a hook's children are covered too.
	if out, err := h.run("cp", "-a", os.Getenv("PRIVILEGE_ROOTFS"), filepath.Join(h.bundle, "rootfs")); err != nil {
		t.Fatalf("copy rootfs: %v %s", err, out)
	}
	if out, err := h.run("runc", "spec", "--bundle", h.bundle); err != nil {
		t.Fatalf("runc spec: %v %s", err, out)
	}
	var spec map[string]any
	data, err := os.ReadFile(filepath.Join(h.bundle, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	process := spec["process"].(map[string]any)
	process["terminal"] = false
	process["args"] = []string{"sh", "-c", "chroot / true; echo $? > /tmp/workload-rc; sleep 60"}
	caps := process["capabilities"].(map[string]any)
	for _, set := range []string{"bounding", "effective", "permitted"} {
		caps[set] = append(caps[set].([]any), "CAP_SYS_CHROOT", "CAP_SYS_ADMIN")
	}
	spec["root"].(map[string]any)["readonly"] = false
	spec["linux"].(map[string]any)["cgroupsPath"] = h.parent + "/container"
	hook := func(path string) []map[string]any {
		return []map[string]any{{"path": path, "args": []string{"sh", "-c", "chroot / true; true"}}}
	}
	// createContainer runs before pivot_root (host path), startContainer after
	// it (container path).
	spec["hooks"] = map[string]any{"createContainer": hook("/bin/sh"), "startContainer": hook("/bin/sh")}
	if data, err = json.Marshal(spec); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.bundle, "config.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	rule := privpolicy.Rule{Name: "no-chroot", Action: "deny", Target: privpolicy.Target{Syscall: []string{"chroot"}}}
	doc := privpolicy.Document{Version: 1, Name: "hooks", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	h.start(t, "privilege-hooks", compiled, extra)
	scope.Container = parentID
	if err := h.bindings.Bind(scope); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.bindings.Unbind(parentID) })
	return h
}

// startContainer runs the bundle detached and returns runc's output.
func (h *hookFixture) startContainer(t *testing.T) (string, error) {
	t.Helper()
	// Output to a file, not a pipe: the container would hold a pipe open
	// until it exits.
	logPath := filepath.Join(h.bundle, "runc.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	start := exec.CommandContext(h.ctx, "runc", "run", "-d", "--bundle", h.bundle, h.id)
	start.Stdout, start.Stderr = logFile, logFile
	err = start.Run()
	logFile.Close()
	t.Cleanup(func() { h.run("runc", "delete", "-f", h.id) })
	out, _ := os.ReadFile(logPath)
	return string(out), err
}

// workloadDenied checks that the workload's first command, chroot, was denied.
func (h *hookFixture) workloadDenied(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var rc []byte
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(filepath.Join(h.bundle, "rootfs", "tmp", "workload-rc")); err == nil && len(data) > 0 {
			rc = data
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if strings.TrimSpace(string(rc)) != "1" {
		t.Fatalf("the workload's first chroot must be denied, rc=%q", rc)
	}
}

// parentScope is the binding of a parent cgroup bound before its containers
// start: it covers them, and it admits the runtime helper exemption.
var parentScope = enforcement.Binding{Subtree: true, RuntimeHelpers: true}

// faultVerdicts counts the operational fault verdicts (hook fault) with this
// mode so far.
func (f *kernelFixture) faultVerdicts(mode uint32) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		hook := strings.ToLower(strings.Fields(e)[0])
		if strings.HasSuffix(hook, "fault") && strings.Contains(e, fmt.Sprintf(" mode=%d ", mode)) {
			n++
		}
	}
	return n
}

// waitFaultVerdict waits up to 5 s for a fault verdict with this mode.
func (f *kernelFixture) waitFaultVerdict(mode uint32) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if f.faultVerdicts(mode) > 0 {
			return true
		}
	}
	return false
}

// chrootVerdicts counts the chroot verdict events so far.
func (f *kernelFixture) chrootVerdicts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		if strings.Contains(e, "chroot") {
			n++
		}
	}
	return n
}

// TestRuntimeHooksJudgedWithoutExemption: a subtree binding without
// RuntimeHelpers has no helper exemption, so both OCI hooks are judged. Their
// chroot is denied (the hooks ignore the result, so the container starts) and
// no exec is exempted.
func TestRuntimeHooksJudgedWithoutExemption(t *testing.T) {
	h := newHookFixture(t, nil, enforcement.Binding{Subtree: true})
	if out, err := h.startContainer(t); err != nil {
		t.Fatalf("container start: %v %s", err, out)
	}
	h.workloadDenied(t)
	// Two hooks and the workload; the events can arrive late.
	for deadline := time.Now().Add(5 * time.Second); h.chrootVerdicts() < 3 && time.Now().Before(deadline); {
		time.Sleep(100 * time.Millisecond)
	}
	if n := h.chrootVerdicts(); n < 3 {
		t.Fatalf("both hooks must be judged with no exemption: %d chroot verdicts, %v", n, h.events)
	}
	if w, err := h.bindings.ArmingWitness(); err != nil || w.ExemptExecs != 0 {
		t.Fatalf("no exec may be exempted: %+v %v", w, err)
	}
}

// TestExactStrictParentDeniesDescendants: a Strict binding without Subtree
// covers its own cgroup only. The container in a child cgroup is outside its
// scope, so its judged checks are denied as a structural fault (with a slot
// fault), never allowed.
func TestExactStrictParentDeniesDescendants(t *testing.T) {
	h := newHookFixture(t, nil, enforcement.Binding{})
	if out, err := h.startContainer(t); err != nil {
		t.Fatalf("container start: %v %s", err, out)
	}
	h.workloadDenied(t)
	if faults, err := h.bindings.SlotFaults(0); err != nil || faults == 0 {
		t.Fatalf("a task outside the exact scope must count a slot fault: %d %v", faults, err)
	}
}

// TestRuntimeHooksAreNotArmed: the OCI createContainer and startContainer
// hooks (and their children) are runtime setup, so they must not be judged
// and the container must start. The workload, a "runc exec" command and every
// task they start must be judged.
func TestRuntimeHooksAreNotArmed(t *testing.T) {
	h := newHookFixture(t, nil, parentScope)
	f, parent, id, run := h.kernelFixture, h.parent, h.id, h.run
	if out, err := h.startContainer(t); err != nil {
		t.Fatalf("the hooks must not be judged, so the container must start: %v %s", err, out)
	}

	h.workloadDenied(t)
	if w, err := h.bindings.ArmingWitness(); err != nil || w.ExemptExecs == 0 {
		t.Errorf("the exempted hook execs must be counted: %+v %v", w, err)
	}
	if out, err := run("runc", "exec", id, "sh", "-c", "unshare -m true && true"); err != nil {
		t.Fatalf("an allowed exec must work: %v %s", err, out)
	}
	denied := func(name string, args ...string) {
		t.Helper()
		if out, err := run("runc", append([]string{"exec", id}, args...)...); err == nil || !strings.Contains(out, "not permitted") {
			t.Errorf("%s: chroot must be denied by the policy: %v %s", name, err, out)
		}
	}
	// An exec command, and tasks that armed tasks start: a forked child, an
	// exec in place, a new mount namespace, and a "runc-like" parent that forks
	// and then execs.
	denied("runc exec", "chroot", "/", "true")
	denied("child", "sh", "-c", "sh -c 'chroot / true'")
	denied("exec in place", "sh", "-c", "exec chroot / true")
	denied("new mount namespace", "unshare", "-m", "sh", "-c", "chroot / true")
	denied("fork then exec", "sh", "-c", "(sleep 0.1; exec chroot / true) & wait $!")

	// A host process that joins the container: nsenter execs the command
	// itself, so its parent is a host task. Moved into the bound cgroup
	// first, so it is judged.
	state, err := run("runc", "state", id)
	if err != nil {
		t.Fatal(err)
	}
	var s struct{ Pid int }
	if err := json.Unmarshal([]byte(state), &s); err != nil {
		t.Fatal(err)
	}
	hostCgroup := filepath.Join("/sys/fs/cgroup", parent, "host")
	if err := os.Mkdir(hostCgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(hostCgroup)
	nsenter := func(fork bool) string {
		args := fmt.Sprintf("echo $$ > %s/cgroup.procs && exec nsenter -t %d -m", hostCgroup, s.Pid)
		if fork {
			args += " -p"
		}
		out, err := run("sh", "-c", args+" chroot / true")
		return fmt.Sprintf("err=%v %s", err, out)
	}
	if out := nsenter(false); !strings.Contains(out, "not permitted") {
		t.Errorf("a host nsenter that execs chroot in a bound cgroup must be denied: %s", out)
	}
	if f.verdicts.Load() == 0 {
		t.Error("no verdict event for the denies")
	}
	// With -p, nsenter forks: the command's parent is the unarmed nsenter inside the
	// container mount namespace, like a runtime helper: not judged. Only a
	// host root process can do this; it is logged, not asserted.
	t.Logf("host nsenter -p (forks) chroot: %s", nsenter(true))
}

// TestWrongRuntimeNamespaceStillJudgesWorkload: with a wrong host-mntns-id,
// the runtime's own tasks are outside the "host" mount namespace too. They
// stay unarmed because each is forked by a runtime task in the same mount
// namespace and cgroup. The workload is in the container mount namespace and
// its parent (runc) is not, so it must still be armed and judged.
func TestWrongRuntimeNamespaceStillJudgesWorkload(t *testing.T) {
	h := newHookFixture(t, map[string]string{"host-mntns-id": "1"}, parentScope)
	if out, err := h.startContainer(t); err != nil {
		t.Logf("container start with a wrong runtime namespace: %v %s", err, out)
		return // judging the runtime itself fails closed
	}
	h.workloadDenied(t)
	if out, err := h.run("runc", "exec", h.id, "chroot", "/", "true"); err == nil || !strings.Contains(out, "not permitted") {
		t.Errorf("runc exec chroot must be denied: %v %s", err, out)
	}
}

// setnsNr is the setns syscall number of the test's architecture.
func setnsNr() int {
	if goruntime.GOARCH == "arm64" {
		return 268
	}
	return 308 // amd64
}

// TestSetnsVerdictsPerCheck pins down that a verdict is one kernel check:
// setns into a mount namespace checks CAP_SYS_ADMIN twice, so audit mode
// reports both checks and enforce mode stops at the first (README, "Maps and
// events").
func TestSetnsVerdictsPerCheck(t *testing.T) {
	for mode, want := range map[string]int32{"audit": 2, "enforce": 1} {
		t.Run(mode, func(t *testing.T) {
			f := newKernelFixture(t)
			rule := privpolicy.Rule{Name: "no-new-mntns", Action: "deny", Target: privpolicy.Target{Syscall: []string{"setns"}, Flags: []string{"CLONE_NEWNS"}}}
			doc := privpolicy.Document{Version: 1, Name: "setns-" + mode, Policy: privpolicy.Policy{Mode: mode, Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
			compiled, err := privpolicy.CompileKernel(doc, 1)
			if err != nil {
				t.Fatal(err)
			}
			f.start(t, "privilege-setns-"+mode, compiled, nil)
			if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
				t.Fatal(err)
			}
			defer f.bindings.Unbind(f.container)
			// One setns(2) call. nsenter is not used: it retries once after
			// EPERM, which gives two syscalls in enforce mode.
			err = f.exec("perl", "-e", fmt.Sprintf(`open(my $f, "<", "/proc/self/ns/mnt") or die; exit(syscall(%d, fileno($f), 0x20000) == 0 ? 0 : 1)`, setnsNr()))
			if (mode == "enforce") != (err != nil) {
				t.Fatalf("setns in %s mode: %v", mode, err)
			}
			time.Sleep(500 * time.Millisecond)
			if got := f.verdicts.Load(); got != want {
				f.mu.Lock()
				defer f.mu.Unlock()
				t.Fatalf("%s: %d verdicts, want %d: %v", mode, got, want, f.events)
			}
		})
	}
}
