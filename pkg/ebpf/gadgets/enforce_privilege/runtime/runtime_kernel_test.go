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
}

func newKernelFixture(t *testing.T) *kernelFixture {
	t.Helper()
	if os.Getenv("PRIVILEGE_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	id, cgroupPath := os.Getenv("PRIVILEGE_CONTAINER_ID"), os.Getenv("PRIVILEGE_CGROUP_PATH")
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", cgroupPath), &st); err != nil {
		t.Fatal(err)
	}
	return &kernelFixture{ctx: ctx, id: id, container: ContainerIdentity{Runtime: "docker", ID: id, CgroupID: st.Ino, CgroupPath: cgroupPath}}
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
	t.Cleanup(func() { manager.StopGadget(context.Background(), desired.Id) })
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
			case "audit":
				if err != nil {
					t.Fatalf("audit mode must allow the fork: %v", err)
				}
				if faults != 0 {
					t.Fatalf("audit faults must not block: %d", faults)
				}
			}
		})
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
// gadget params.
func newHookFixture(t *testing.T, extra map[string]string) *hookFixture {
	t.Helper()
	if os.Getenv("PRIVILEGE_KERNEL_TEST") != "1" || os.Getenv("PRIVILEGE_ROOTFS") == "" {
		t.Skip("explicit disposable kernel fixture opt-in and PRIVILEGE_ROOTFS required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
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
	if err := h.bindings.Bind(enforcement.Binding{Container: parentID}); err != nil {
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

// TestRuntimeHooksAreNotArmed: the OCI createContainer and startContainer
// hooks (and their children) are runtime setup, so they must not be judged
// and the container must start. The workload, a "runc exec" command and every
// task they start must be judged.
func TestRuntimeHooksAreNotArmed(t *testing.T) {
	h := newHookFixture(t, nil)
	f, parent, id, run := h.kernelFixture, h.parent, h.id, h.run
	if out, err := h.startContainer(t); err != nil {
		t.Fatalf("the hooks must not be judged, so the container must start: %v %s", err, out)
	}

	h.workloadDenied(t)
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
	h := newHookFixture(t, map[string]string{"host-mntns-id": "1"})
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
