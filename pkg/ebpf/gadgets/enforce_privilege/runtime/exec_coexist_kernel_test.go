//go:build linux && privilege_kernel && enforce_exec_shared_qualification

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

// TestTaskAllocWithSharedExec runs this gadget next to enforce_exec's real
// shared node (IG's product object, started through IG's qualification seam)
// on one cgroup. Both own task_alloc: the shared node allocates TASK state
// for a child (its birth park), and the kernel calls task_free when a later
// task_alloc program refuses the fork. Requires root, BPF LSM and an exact
// pinned kernel (AL2023 amd64 6.12.113-138.209 or 6.18.56-125.164):
//
//	PRIVILEGE_KERNEL_TEST=1, PRIVILEGE_IMAGE_ARCHIVE, PRIVILEGE_IMAGE  as in runtime_kernel_test.go
//	PRIVILEGE_EXEC_OBJECT       IG's product object for this kernel (g19pkg128-<6.12|6.18>.bpf.o,
//	                            from `make enforce-exec-product-objects` at the pinned IG commit)
//	PRIVILEGE_EXEC_CGROUP_ROOT  an empty parent cgroup under /sys/fs/cgroup, one level deep;
//	                            the test creates and removes its children
//
// A C compiler (cc, with glibc-static on AL2023) builds the clone helper: a
// Go helper would add thread clones to the birth counts.

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"golang.org/x/sys/unix"
	"oras.land/oras-go/v2/content/memory"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
)

// execProfile is the geometry of the product object g19pkg128 (q(128,32)).
var execProfile = fullruntime.SharedProfile{
	Version: 1, CandidateBytes: 1 << 20, Bindings: 2, PolicySlots: [4]uint64{4, 0, 0, 0},
	Tasks: 256, Scratch: 64, InodeFacts: 2, AcceptedUIDs: 8, Images: 256,
	CompileBytes: 8 << 20, CompileConcurrency: 2, TelemetryBytes: 4096, RolloutBytes: 4096, PossibleCPUs: 64,
	PerBinding:     fullruntime.SharedQuota{Tasks: 128, Scratch: 32, InodeFacts: 1, AcceptedUIDs: 4, Images: 128},
	ExitTombstones: 8192,
}

// execSymbols are the failure-frame symbols of each pinned kernel (IG's
// sharedProductPins).
var execSymbols = map[string][2]string{
	"6.12.113-138.209.amzn2023.x86_64": {"do_execveat_common.isra.0", "search_binary_handler"},
	"6.18.56-125.164.amzn2023.x86_64":  {"do_execveat_common.isra.0", "exec_binprm"},
}

// cloneHelper forks once with raw clone(2), with CLONE_NEWNS when its
// argument is "newns". It exits with the clone errno, 0 when the child ran.
const cloneHelper = `#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
	unsigned long flags = SIGCHLD;
	if (argc > 1 && !strcmp(argv[1], "newns"))
		flags |= CLONE_NEWNS;
	long pid = syscall(SYS_clone, flags, 0, 0, 0, 0);
	if (pid == 0)
		_exit(0);
	if (pid < 0)
		return errno;
	int status;
	if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status))
		return 100;
	return 0;
}
`

func TestTaskAllocWithSharedExec(t *testing.T) {
	if os.Getenv("PRIVILEGE_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	object, root := os.Getenv("PRIVILEGE_EXEC_OBJECT"), os.Getenv("PRIVILEGE_EXEC_CGROUP_ROOT")
	if object == "" || root == "" {
		t.Skip("set PRIVILEGE_EXEC_OBJECT and PRIVILEGE_EXEC_CGROUP_ROOT")
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	if _, ok := execSymbols[release]; !ok {
		t.Skipf("kernel %s is not a pinned shared-node kernel", release)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "clone-helper")
	source := helper + ".c"
	if err := os.WriteFile(source, []byte(cloneHelper), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O2", "-static", "-o", helper, source).CombinedOutput(); err != nil {
		t.Fatalf("build the clone helper: %v: %s", err, out)
	}
	leaf := 0
	for _, execMode := range []fullpolicy.Mode{fullpolicy.Enforce, fullpolicy.Audit} {
		for _, privMode := range []string{"enforce", "audit"} {
			t.Run(fmt.Sprintf("exec-%s/privilege-%s", execMode, privMode), func(t *testing.T) {
				ran := map[bool]bool{}
				for _, privilegeFirst := range []bool{true, false} {
					name := "privilege attached last"
					if privilegeFirst {
						name = "privilege attached first"
					}
					leaf++
					t.Run(name, func(t *testing.T) {
						c := coexistCase{object: object, cgroup: filepath.Join(root, fmt.Sprintf("leaf-%d", leaf)), helper: helper,
							execMode: execMode, privMode: privMode, privilegeFirst: privilegeFirst}
						ran[privilegeFirst] = c.run(t)
					})
				}
				if t.Failed() || privMode != "enforce" {
					return
				}
				t.Logf("the shared node built a TASK for the denied fork before the privilege deny: privilege first %v, privilege last %v", ran[true], ran[false])
				if ran[true] == ran[false] {
					t.Fatalf("the shared node built a TASK for the denied fork in %v of both orders; want exactly one order", ran[true])
				}
			})
		}
	}
}

type coexistCase struct {
	object, cgroup, helper string
	execMode               fullpolicy.Mode
	privMode               string
	privilegeFirst         bool
}

// run returns whether the shared node parked and built a TASK for the
// denied fork before this gadget refused it (read from the birth park
// counts).
func (c coexistCase) run(t *testing.T) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	cleanPins(t)
	if err := os.Mkdir(c.cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeCgroup(c.cgroup) })
	var st unix.Stat_t
	if err := unix.Stat(c.cgroup, &st); err != nil {
		t.Fatal(err)
	}
	f := &kernelFixture{ctx: ctx, id: "privilege-exec-coexist", container: ContainerIdentity{
		Runtime: "docker", ID: "privilege-exec-coexist", CgroupID: st.Ino, CgroupPath: strings.TrimPrefix(c.cgroup, "/sys/fs/cgroup"),
	}}
	startPrivilege := func() {
		rule := privpolicy.Rule{Name: "no-newns", Action: "deny", Target: privpolicy.Target{Syscall: []string{"clone", "clone3"}, Flags: []string{"CLONE_NEWNS"}}}
		doc := privpolicy.Document{Version: 1, Name: "exec-coexist", Policy: privpolicy.Policy{Mode: c.privMode, Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
		compiled, err := privpolicy.CompileKernel(doc, 1)
		if err != nil {
			t.Fatal(err)
		}
		f.start(t, "privilege-exec-coexist", compiled, nil)
		if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
			t.Fatal(err)
		}
	}
	if c.privilegeFirst {
		startPrivilege()
	}
	n := startSharedExec(t, ctx, c.object)
	init := startPipeInit(t, c.cgroup)
	session, err := n.node.Bind(ctx, fullruntime.SharedBindingConfig{CgroupID: st.Ino, InitHostPID: uint32(init.cmd.Process.Pid), Acquire: init.acquire})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	policy := &fullpolicy.Policy{ID: "exec-coexist", Revision: "1", Mode: c.execMode, RootRole: "app", Default: fullpolicy.Deny,
		Rules: []fullpolicy.Rule{{Name: "root", Action: fullpolicy.Allow, Actor: fullpolicy.Actor{UID: []int64{0}}}}}
	if _, err := session.Publish(ctx, fullruntime.SharedBindingPolicy{Source: policy, Container: "coexist"}); err != nil {
		t.Fatalf("Publish (adoption): %v", err)
	}
	if !c.privilegeFirst {
		startPrivilege()
	}
	if h, err := n.node.FailClosedHealth(); err != nil || !h.Gated || !h.Product {
		t.Fatalf("fail-closed witness %+v (%v): want a gated product witness", h, err)
	}
	tasks, works := n.accounts(t)
	t.Logf("TASK/WORK baseline after adoption: %d/%d", tasks, works)

	// round runs the helper in the adopted init and checks that every exec
	// credit returns to the baseline with no fault. It returns the helper's
	// exit code and the birth park delta.
	round := func(label, arg string) (int, fullruntime.SharedBirthParkHealth) {
		t.Helper()
		park := n.park(t)
		capsule, err := n.node.CapsuleHealth()
		if err != nil {
			t.Fatal(err)
		}
		code := init.run(ctx, t, c.helper+" "+arg)
		n.settle(t, label, tasks, works)
		// Every parked birth is taken or abandoned, with no fault (polled:
		// the counts can trail the settle).
		var delta fullruntime.SharedBirthParkHealth
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			after := n.park(t)
			delta = fullruntime.SharedBirthParkHealth{
				Parked: after.Parked - park.Parked, Taken: after.Taken - park.Taken, Abandoned: after.Abandoned - park.Abandoned,
				Stale: after.Stale - park.Stale, PutFailed: after.PutFailed - park.PutFailed, Latched: after.Latched - park.Latched,
				TakeFailed: after.TakeFailed - park.TakeFailed, CrossGeneration: after.CrossGeneration - park.CrossGeneration,
			}
			if delta.Parked == delta.Taken+delta.Abandoned || time.Now().After(deadline) {
				break
			}
		}
		t.Logf("%s: exit %d, birth park delta %+v", label, code, delta)
		if delta.Parked != delta.Taken+delta.Abandoned || delta.Stale != 0 || delta.PutFailed != 0 || delta.Latched != 0 || delta.TakeFailed != 0 {
			t.Fatalf("%s: birth park %+v: every parked birth must be taken or abandoned, with no fault", label, delta)
		}
		if now, err := n.node.CapsuleHealth(); err != nil || now.Faults != capsule.Faults || now.ReleaseFaults != capsule.ReleaseFaults {
			t.Fatalf("%s: capsule health %+v (before %+v): %v", label, now, capsule, err)
		}
		n.requireHealthy(t, label)
		return code, delta
	}
	code, control := round("plain fork", "plain")
	if code != 0 {
		t.Fatalf("plain fork: exit %d, want 0", code)
	}
	if v := f.cloneVerdicts(0); len(v) != 0 {
		t.Fatalf("plain fork: privilege verdicts %v, want none", v)
	}
	code, denied := round("CLONE_NEWNS fork", "newns")
	want := 0
	if c.privMode == "enforce" {
		want = int(unix.EPERM)
	}
	if code != want {
		t.Fatalf("CLONE_NEWNS fork: exit %d, want %d (privilege %s)", code, want, c.privMode)
	}
	// The verdict shows that this gadget judged the fork, in both modes:
	// an EPERM alone could also come from the shared node.
	if v := f.cloneVerdicts(1); len(v) != 1 {
		t.Fatalf("CLONE_NEWNS fork: privilege task_alloc verdicts %v, want exactly one", v)
	}
	if code, _ := round("next plain fork", "plain"); code != 0 {
		t.Fatalf("next plain fork: exit %d, want 0", code)
	}
	if v := f.cloneVerdicts(1); len(v) != 1 {
		t.Fatalf("after the next plain fork: privilege task_alloc verdicts %v, want still one", v)
	}
	// The plain and the denied round differ only in the clone flag: the
	// denied round parks as many births when the shared node ran for the
	// denied fork, one fewer when this gadget denied it first.
	switch {
	case denied.Parked == control.Parked:
		if c.privMode == "enforce" && (denied.Taken != denied.Parked || denied.Abandoned != 0) {
			t.Fatalf("the shared node ran for the denied fork but did not build its TASK: %+v", denied)
		}
		return c.privMode == "enforce"
	case denied.Parked+1 == control.Parked && c.privMode == "enforce":
		return false
	}
	t.Fatalf("the denied fork parked %d births, the plain fork %d", denied.Parked, control.Parked)
	return false
}

// cloneVerdicts waits up to 3 s for want task_alloc verdicts of the clone
// helper and returns them.
func (f *kernelFixture) cloneVerdicts(want int) []string {
	var out []string
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		out = out[:0]
		f.mu.Lock()
		for _, e := range f.events {
			fields := strings.Fields(e)
			if strings.Contains(strings.ToLower(fields[0]), "task_alloc") && fields[len(fields)-1] == "clone-helper" {
				out = append(out, e)
			}
		}
		f.mu.Unlock()
		if len(out) >= want || time.Now().After(deadline) {
			return out
		}
	}
}

type sharedExec struct {
	node *fullruntime.NodeEnforcer
	gc   operators.GadgetContext
}

// startSharedExec starts the shared node from the product object, as IG's
// qualification start does (fullruntime.BuildSharedCandidateImage).
func startSharedExec(t *testing.T, ctx context.Context, object string) *sharedExec {
	t.Helper()
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	symbols := execSymbols[release]
	elf, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	image, err := fullruntime.BuildSharedCandidateImage(ctx, store, elf, fullruntime.KernelMatrixEntry{
		Release: release, OuterSymbol: symbols[0], HandlerSymbol: symbols[1], Profile: execProfile,
	})
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
	n := &sharedExec{}
	capture := simple.New("privilege-exec-coexist", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		n.gc = gc
		return nil
	}))
	const id = "privilege-exec-coexist-node"
	run := func(ctx context.Context, opt gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
		desired := &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: image}}
		err := manager.StartGadget(ctx, desired, gadgetcontext.WithOrasReadonlyTarget(store),
			gadgetcontext.WithAdditionalDataOperators(handler, fullruntime.New(), capture), opt)
		done := make(chan error, 1)
		if gi := manager.LookupInstance(id); gi != nil {
			go func() { done <- gi.WaitStopped(context.Background()) }()
		}
		stop := func(ctx context.Context) error {
			if err := manager.StopGadget(ctx, id); err != nil && !errors.Is(err, instancemanager.ErrNotFound) {
				return err
			}
			return nil
		}
		return stop, done, err
	}
	node, err := fullruntime.StartNode(fullruntime.WithSharedNodeQualification(ctx, fullruntime.SharedNodeQualification{Run: run}),
		fullruntime.SharedNodeConfig{Profile: execProfile, ABI3Development: true, Image: image, FailClosedPollInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("StartNode: %v", err)
	}
	t.Cleanup(func() {
		if err := node.StopNode(context.WithoutCancel(ctx)); err != nil {
			t.Errorf("StopNode: %v", err)
		}
	})
	n.node = node
	return n
}

func (n *sharedExec) mapOf(t *testing.T, name string) *ebpf.Map {
	t.Helper()
	value, _ := n.gc.GetVar(operators.MapPrefix + name)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		t.Fatalf("shared node map %s not published", name)
	}
	return m
}

// accounts sums the used TASK and WORK credits of every binding account; a
// faulted account fails the test.
func (n *sharedExec) accounts(t *testing.T) (tasks, works uint32) {
	t.Helper()
	for i, name := range []string{"se_opaque_accounts", "se_opaque_work_accounts"} {
		m := n.mapOf(t, name)
		for a := uint32(0); a < m.MaxEntries(); a++ {
			raw, err := m.LookupBytes(a)
			if err != nil || len(raw) < 12 {
				t.Fatalf("%s[%d]: %v", name, a, err)
			}
			// Layout: lock, used, fault, incarnation.
			if fault := binary.LittleEndian.Uint32(raw[8:12]); fault != 0 {
				t.Fatalf("%s[%d] faulted (fault word %#x)", name, a, fault)
			}
			if used := binary.LittleEndian.Uint32(raw[4:8]); i == 0 {
				tasks += used
			} else {
				works += used
			}
		}
	}
	return tasks, works
}

// settle waits until every TASK and WORK credit is back at the baseline and
// no exec terminal receipt is left: task_free released the state of every
// child, denied or not.
func (n *sharedExec) settle(t *testing.T, label string, tasks, works uint32) {
	t.Helper()
	receipts := n.mapOf(t, "se_exec_terminal_receipts")
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(5 * time.Millisecond) {
		gotTasks, gotWorks := n.accounts(t)
		var key uint64
		var value []byte
		stray := receipts.Iterate().Next(&key, &value)
		if gotTasks == tasks && gotWorks == works && !stray {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: TASK/WORK %d/%d (baseline %d/%d), stray receipt %v: exec state leaked", label, gotTasks, gotWorks, tasks, works, stray)
		}
	}
}

func (n *sharedExec) park(t *testing.T) fullruntime.SharedBirthParkHealth {
	t.Helper()
	h, err := n.node.BirthParkHealth()
	if err != nil {
		t.Fatalf("the product object has no birth park: %v", err)
	}
	return h
}

// requireHealthy waits up to 5 s for the fail-closed witness to be Healthy.
func (n *sharedExec) requireHealthy(t *testing.T, label string) {
	t.Helper()
	var h fullruntime.SharedFailClosedHealth
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if h, err = n.node.FailClosedHealth(); err == nil && h.State == fullruntime.SharedFailClosedHealthy {
			return
		}
	}
	t.Fatalf("%s: fail-closed health %+v: %v", label, h, err)
}

// pipeInit is a container-like init: a shell cloned directly into the
// cgroup with its own mount namespace, which runs each line it reads (as
// IG's attached tests do). The shared node adopts it.
type pipeInit struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *bufio.Reader
	path string
}

func startPipeInit(t *testing.T, cgroup string) *pipeInit {
	t.Helper()
	dir, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	// bash survives a refused fork.
	cmd := exec.Command("/bin/bash", "-c", `while IFS= read -r line; do /bin/bash -c "$line"; echo "@@done $?"; done`)
	cmd.Args[0] = "privilege-exec-coexist-init"
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the init in %s: %v", cgroup, err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return &pipeInit{cmd: cmd, in: in, out: bufio.NewReader(out), path: cgroup}
}

// run runs line in the init and returns its exit status. When ctx ends it
// kills the fixture cgroup, so the init and every descendant close the pipe
// and the read returns.
func (p *pipeInit) run(ctx context.Context, t *testing.T, line string) int {
	t.Helper()
	stop := context.AfterFunc(ctx, func() { _ = os.WriteFile(filepath.Join(p.path, "cgroup.kill"), []byte("1"), 0) })
	defer stop()
	if _, err := io.WriteString(p.in, line+"\n"); err != nil {
		t.Fatal(err)
	}
	for {
		l, err := p.out.ReadString('\n')
		if err != nil {
			t.Fatalf("%q: init output: %v", line, err)
		}
		var code int
		if _, err := fmt.Sscanf(l, "@@done %d", &code); err == nil {
			return code
		}
	}
}

// pipeLease is the trusted lease over the init the test started.
type pipeLease struct{ proc, cgroup, mount, hostMount *os.File }

func (*pipeLease) Check(context.Context) error    { return nil }
func (l *pipeLease) InitProc() *os.File           { return l.proc }
func (l *pipeLease) Cgroup() *os.File             { return l.cgroup }
func (l *pipeLease) MountNamespace() *os.File     { return l.mount }
func (l *pipeLease) HostMountNamespace() *os.File { return l.hostMount }
func (l *pipeLease) Close() error {
	var result error
	for _, f := range []*os.File{l.proc, l.cgroup, l.mount, l.hostMount} {
		if f != nil {
			result = errors.Join(result, f.Close())
		}
	}
	return result
}

func (p *pipeInit) acquire(context.Context) (fullruntime.BindingLease, error) {
	pid := p.cmd.Process.Pid
	l := &pipeLease{}
	var err error
	open := func(path string, flags int) *os.File {
		f, e := os.OpenFile(path, flags, 0)
		err = errors.Join(err, e)
		return f
	}
	l.proc = open(fmt.Sprintf("/proc/%d", pid), unix.O_DIRECTORY|unix.O_RDONLY)
	l.cgroup = open(p.path, unix.O_DIRECTORY|unix.O_RDONLY)
	l.mount = open(fmt.Sprintf("/proc/%d/ns/mnt", pid), unix.O_RDONLY)
	l.hostMount = open("/proc/self/ns/mnt", unix.O_RDONLY)
	return l, err
}

// removeCgroup kills every task of the cgroup and removes it.
func removeCgroup(path string) {
	_ = os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if os.Remove(path) == nil {
			return
		}
	}
}
