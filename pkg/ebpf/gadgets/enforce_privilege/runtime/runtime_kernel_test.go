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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
		return gc.GetDataSources()["verdict"].Subscribe(func(datasource.DataSource, datasource.Data) error {
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
