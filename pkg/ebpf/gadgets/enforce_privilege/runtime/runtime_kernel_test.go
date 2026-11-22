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
// POSIX sh, and perl for TestSetnsVerdictsPerCheck (busybox has none; for
// example debian:13-slim with perl). TestTaskAllocCoexistence reads busybox
// sh's fork errors ("Out of memory", "Permission denied"; dash prints only
// "Cannot fork"): run it alone in a busybox container (it skips in another). On an AppArmor host, also start it with
// --security-opt apparmor=unconfined: docker-default blocks the unbound
// unshare, setns and raw socket baselines. Run the tests from this directory
// (go test does; a binary built with go test -c must be started here):
// TestProgramsMatchSource and TestHooksMatchProgram read ../program.bpf.c.
// TestEarlierBPFDenyHolds loads a BPF LSM program that denies every chroot on
// the node for a few seconds.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"slices"
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
	if err := enforcement.RemovePinnedMaps(MapPrefix); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { enforcement.RemovePinnedMaps(MapPrefix) })
}

// start runs the gadget with the compiled documents and extra ebpf params.
func (f *kernelFixture) start(t *testing.T, name string, compiled privpolicy.Compiled, extra map[string]string) {
	t.Helper()
	if err := f.startConfig(t, name, Config{Policy: compiled, FaultInjection: len(extra) > 0}, extra); err != nil {
		t.Fatal(err)
	}
}

// startConfig starts the gadget with config and the extra gadget parameters.
func (f *kernelFixture) startConfig(t *testing.T, name string, config Config, extra map[string]string) error {
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
		WithConfig(config)); err != nil {
		return err
	}
	f.stop = func() { manager.StopGadget(context.Background(), desired.Id) }
	t.Cleanup(f.stop)
	return nil
}

// TestTestSwitchesForcedOff: a production instance (no FaultInjection) with a
// test-only switch set by a parameter loads with the switch at 0 (the owner
// forces it before the load), so it starts and judges as usual: an armed
// shell forks, and a denied call is denied.
func TestTestSwitchesForcedOff(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-newns", Action: "deny", Target: privpolicy.Target{Syscall: []string{"unshare"}, Flags: []string{"CLONE_NEWNS"}}}
	doc := privpolicy.Document{Version: 1, Name: "switches-off", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	c, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, param := range []string{"arming-fail-fork-marks", "arming-fail-exec-marks", "policy-fail-headers", "cred-record-fail", "cred-forget-fail"} {
		t.Run(param, func(t *testing.T) {
			if err := f.startConfig(t, "privilege-switch-"+param, Config{Policy: c}, map[string]string{param: "1"}); err != nil {
				t.Fatalf("start = %v, want the switch forced to 0", err)
			}
			// The next subtest starts on empty state, also after a failure.
			t.Cleanup(func() {
				f.bindings.Unbind(f.container)
				f.stop()
				_ = enforcement.RemovePinnedMaps(MapPrefix)
			})
			if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
				t.Fatal(err)
			}
			if err := f.exec("sh", "-c", "true & wait"); err != nil {
				t.Fatalf("an armed fork must work: %v", err)
			}
			if err := f.exec("unshare", "-m", "true"); err == nil {
				t.Fatal("the deny must hold")
			}
			if n, err := f.bindings.SlotFaults(0); err != nil || n != 0 {
				t.Fatalf("no fault with the switch forced off: %d %v", n, err)
			}
		})
	}
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
			f.start(t, "privilege-fault-"+mode, compiled, map[string]string{"arming-fail-fork-marks": "1"})
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
				// The lost judgement is counted for the fail rate.
				if c, err := f.bindings.Counters(0); err != nil || c.Unevaluated == 0 || c.Attempts == 0 {
					t.Fatalf("a lost Audit mark counts an unevaluated judgement and an attempt: %+v %v", c, err)
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

// TestExecMarkFaultInjection makes every exec mark fail. The mark is prepared
// in bprm_check_security, where the exec can still fail: a Strict binding
// refuses the exec and counts a fault; an Audit binding runs it and counts an
// unevaluated judgement, never a fault.
func TestExecMarkFaultInjection(t *testing.T) {
	for _, mode := range []string{"enforce", "audit"} {
		t.Run(mode, func(t *testing.T) {
			f := newKernelFixture(t)
			rule := privpolicy.Rule{Name: "no-modules", Action: "deny", Target: privpolicy.Target{Syscall: []string{"init_module"}}}
			doc := privpolicy.Document{Version: 1, Name: "exec-fault-" + mode, Policy: privpolicy.Policy{Mode: mode, Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
			compiled, err := privpolicy.CompileKernel(doc, 1)
			if err != nil {
				t.Fatal(err)
			}
			f.start(t, "privilege-exec-fault-"+mode, compiled, map[string]string{"arming-fail-exec-marks": "1"})
			run := func() error { return f.exec("true") }
			if err := run(); err != nil {
				t.Fatalf("an unbound container must not be judged: %v", err)
			}
			if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
				t.Fatal(err)
			}
			defer f.bindings.Unbind(f.container)
			before, err := f.bindings.Counters(0)
			if err != nil {
				t.Fatal(err)
			}
			err = run()
			after, cerr := f.bindings.Counters(0)
			if cerr != nil {
				t.Fatal(cerr)
			}
			if after.Attempts <= before.Attempts {
				t.Fatalf("the exec counts an attempt: %+v -> %+v", before, after)
			}
			switch mode {
			case "enforce":
				if err == nil {
					t.Fatal("an exec whose mark cannot be allocated must be refused under Strict")
				}
				if after.Faults <= before.Faults {
					t.Fatalf("the refused exec counts a fault: %+v -> %+v", before, after)
				}
			case "audit":
				if err != nil {
					t.Fatalf("audit mode must run the exec: %v", err)
				}
				if after.Faults != before.Faults || after.Unevaluated <= before.Unevaluated {
					t.Fatalf("a lost Audit exec mark is unevaluated, not a fault: %+v -> %+v", before, after)
				}
			}
		})
	}
}

// threadExecHelper starts a thread that execs the helper again; the new
// program tries a new mount namespace. Exit 1 means EPERM, 0 allowed.
const threadExecHelper = `#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void *run(void *arg)
{
	char *argv[] = {"thread-exec", "child", NULL};

	execv("/proc/self/exe", argv);
	perror("execv");
	_exit(3);
}

int main(int argc, char **argv)
{
	pthread_t th;

	if (argc > 1) {
		if (unshare(CLONE_NEWNS) == 0) {
			puts("unshare allowed");
			return 0;
		}
		printf("unshare: %s\n", strerror(errno));
		return errno == EPERM ? 1 : 2;
	}
	if (pthread_create(&th, NULL, run, NULL))
		return 4;
	pthread_join(th, NULL);
	return 5;
}
`

// TestThreadExecKeepsArming covers a thread whose own mark failed at fork: it
// is covered through its armed group leader. Its exec makes it the leader, so
// the exec preparation gives it its own mark and the new program stays
// judged, with no fault.
func TestThreadExecKeepsArming(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-newns", Action: "deny", Target: privpolicy.Target{Syscall: []string{"unshare"}, Flags: []string{"CLONE_NEWNS"}}}
	doc := privpolicy.Document{Version: 1, Name: "thread-exec", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "thread-exec")
	if err := os.WriteFile(helper+".c", []byte(threadExecHelper), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O2", "-static", "-pthread", "-o", helper, helper+".c").CombinedOutput(); err != nil {
		t.Fatalf("build the helper: %v: %s", err, out)
	}
	if out, err := exec.CommandContext(f.ctx, "docker", "cp", helper, f.id+":/thread-exec").CombinedOutput(); err != nil {
		t.Fatalf("copy the helper: %v: %s", err, out)
	}
	// Every child mark fails at fork: a new thread is covered only through
	// its leader.
	f.start(t, "privilege-thread-exec", compiled, map[string]string{"arming-fail-fork-marks": "1"})
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatal(err)
	}
	defer f.bindings.Unbind(f.container)
	before, err := f.bindings.Counters(0)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, "/thread-exec").CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("the program a covered thread execs must stay judged (want EPERM): %v: %s", err, out)
	}
	after, err := f.bindings.Counters(0)
	if err != nil {
		t.Fatal(err)
	}
	if after.Faults != before.Faults {
		t.Fatalf("the thread's exec must not lose its mark: %+v -> %+v", before, after)
	}
}

// ioUringPersonalityHelper registers an io_uring personality (its current
// credentials), drops every capability with capset, then creates a raw socket
// through that personality: inline in io_uring_enter, or in an io-wq worker
// with the argument "async". Exit 0: created, 1: EPERM, else a setup error.
const ioUringPersonalityHelper = `#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int ring, sqpoll;
static size_t sq_size, cq_size;
static unsigned pending;
static struct io_uring_params p;
static char *sq, *cq;
static struct io_uring_sqe *sqes;

static void fail(const char *what) { perror(what); exit(3); }

static void setup_flags(unsigned flags)
{
	size_t sqsz, cqsz;

	memset(&p, 0, sizeof(p));
	p.flags = flags;
	p.sq_thread_idle = 1000;
	sqpoll = flags & IORING_SETUP_SQPOLL;
	ring = syscall(__NR_io_uring_setup, 8, &p);
	if (ring < 0) fail("io_uring_setup");
	sqsz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	cqsz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
	if (p.features & IORING_FEAT_SINGLE_MMAP && cqsz > sqsz)
		sqsz = cqsz;
	sq_size = sqsz;
	cq_size = cqsz;
	sq = mmap(0, sqsz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQ_RING);
	cq = (p.features & IORING_FEAT_SINGLE_MMAP) ? sq :
	     mmap(0, cqsz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_CQ_RING);
	sqes = mmap(0, p.sq_entries * sizeof(*sqes), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQES);
	if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED) fail("mmap");
}

static void setup(void) { setup_flags(0); }

// sqe returns the next free entry, zeroed; submit publishes the pending ones.
static struct io_uring_sqe *sqe(void)
{
	unsigned t = *(unsigned *)(sq + p.sq_off.tail) + pending;
	unsigned i = t & *(unsigned *)(sq + p.sq_off.ring_mask);

	memset(&sqes[i], 0, sizeof(sqes[i]));
	((unsigned *)(sq + p.sq_off.array))[i] = i;
	pending++;
	return &sqes[i];
}

static void submit(void)
{
	unsigned *tail = (unsigned *)(sq + p.sq_off.tail), n = pending;

	__atomic_store_n(tail, *tail + n, __ATOMIC_RELEASE);
	pending = 0;
	// With SQPOLL the ring's thread submits; the call only wakes it.
	if (syscall(__NR_io_uring_enter, ring, n, 0, sqpoll ? IORING_ENTER_SQ_WAKEUP : 0, NULL, 0) < 0) fail("io_uring_enter");
}

// reap waits for the completion of user_data and returns its result.
static int reap(__u64 user_data)
{
	struct io_uring_cqe *cqes = (struct io_uring_cqe *)(cq + p.cq_off.cqes);
	unsigned *head = (unsigned *)(cq + p.cq_off.head);
	unsigned mask = *(unsigned *)(cq + p.cq_off.ring_mask);

	for (;;) {
		unsigned tail = __atomic_load_n((unsigned *)(cq + p.cq_off.tail), __ATOMIC_ACQUIRE);

		while (*head != tail) {
			struct io_uring_cqe *c = &cqes[*head & mask];
			__u64 ud = c->user_data;
			int res = c->res;

			__atomic_store_n(head, *head + 1, __ATOMIC_RELEASE);
			if (ud == user_data) return res;
		}
		if (syscall(__NR_io_uring_enter, ring, 0, 1, IORING_ENTER_GETEVENTS, NULL, 0) < 0) fail("io_uring_enter");
	}
}

static int personality(void)
{
	int id = syscall(__NR_io_uring_register, ring, IORING_REGISTER_PERSONALITY, NULL, 0);

	if (id < 0) fail("register personality");
	return id;
}

// caps commits new credentials: with no capabilities, or with the same ones
// (a new credential pointer).
static void caps(int keep)
{
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2];

	memset(d, 0, sizeof(d));
	if (keep && syscall(__NR_capget, &h, d)) fail("capget");
	if (syscall(__NR_capset, &h, d)) fail("capset");
}

static void raw_socket(int id, int flags)
{
	struct io_uring_sqe *e = sqe();

	e->opcode = IORING_OP_SOCKET;
	e->fd = AF_INET;
	e->off = SOCK_RAW;
	e->len = IPPROTO_ICMP;
	e->personality = id;
	e->flags = flags;
	e->user_data = 1;
}

static void nop(int id, int flags, __u64 user_data)
{
	struct io_uring_sqe *e = sqe();

	e->opcode = IORING_OP_NOP;
	e->personality = id;
	e->flags = flags;
	e->user_data = user_data;
}

// close_ring unmaps the ring and closes it: nothing holds it any more.
static void close_ring(void)
{
	munmap(sqes, p.sq_entries * sizeof(*sqes));
	if (cq != sq)
		munmap(cq, cq_size);
	munmap(sq, sq_size);
	close(ring);
}

// io_wq_worker reports whether an io-wq worker of this process runs.
static int io_wq_worker(void)
{
	char path[64], comm[32];
	struct dirent *d;
	int found = 0;
	DIR *dir = opendir("/proc/self/task");

	if (!dir) fail("opendir");
	while (!found && (d = readdir(dir))) {
		FILE *f;

		snprintf(path, sizeof(path), "/proc/self/task/%s/comm", d->d_name);
		f = fopen(path, "r");
		if (!f)
			continue;
		found = fgets(comm, sizeof(comm), f) && !strncmp(comm, "iou-wrk-", 8);
		fclose(f);
	}
	closedir(dir);
	return found;
}

// wait_bound marks the helper ready (/tmp/ready), then waits until the test
// has bound the container (/tmp/bound).
static void wait_bound(void)
{
	int fd = open("/tmp/ready", O_CREAT | O_WRONLY, 0644);

	if (fd < 0) fail("ready");
	close(fd);
	while (access("/tmp/bound", F_OK))
		usleep(10000);
}

// linked_socket runs a raw socket request under personality id from
// task_work: linked behind a pipe read that write() releases.
static int linked_socket(int id)
{
	struct io_uring_sqe *e;
	int fds[2];
	char b;

	if (pipe(fds)) fail("pipe");
	e = sqe();
	e->opcode = IORING_OP_READ;
	e->fd = fds[0];
	e->addr = (unsigned long)&b;
	e->len = 1;
	e->flags = IOSQE_IO_LINK;
	e->user_data = 3;
	raw_socket(id, 0);
	submit();
	if (write(fds[1], "x", 1) != 1) fail("write");
	return reap(1);
}

// raw_async_thread submits an async raw socket request from another thread,
// which keeps the credentials it was created with (credentials are per
// thread).
static int thread_res, thread_go;
static void *raw_async_thread(void *arg)
{
	(void)arg;
	while (!__atomic_load_n(&thread_go, __ATOMIC_ACQUIRE))
		usleep(1000);
	raw_socket(0, IOSQE_ASYNC);
	submit();
	thread_res = reap(1);
	return NULL;
}

// sqpoll_thread sets up an SQPOLL ring and exits; the ring stays.
static void *sqpoll_thread(void *arg)
{
	(void)arg;
	setup_flags(IORING_SETUP_SQPOLL);
	return NULL;
}

// Modes:
//   postbind-ring: after the bind, sets up a ring (with an io-wq worker), then
//     waits for /tmp/release; on /tmp/close it closes the ring first
//     (/tmp/closed) and keeps running.
//   prebind-thread: before the bind, a second thread starts with the exec
//     credentials and the main thread commits new ones; no ring exists yet.
//     After the bind, the main thread sets up a ring and starts an io-wq
//     worker (with its new credentials), and the second thread sends a raw
//     socket request: the worker runs it under the second thread's exec
//     credentials, which only the bind walk recorded.
//   prebind-personality: before the bind, a personality holds the exec
//     credentials, then capset commits new ones; after the bind, the
//     personality runs a request inline and one from task_work. Only the
//     personality holds the exec credentials at the bind.
//   prebind-async: before the bind, an io-wq worker starts and capset commits
//     new credentials; after the bind, a request runs in the worker under the
//     submitter's credentials, which it held at the bind.
//   prebind-sqpoll: before the bind, an SQPOLL ring starts and capset commits
//     new credentials; after the bind, the ring's thread runs a request.
//   prebind-closed: before the bind, a ring runs async work (an io-wq worker
//     starts), then the ring is closed. On 6.12 the worker stays (io-wq is
//     per task); on 6.18 it ends with the ring. Exit 0 when a worker ran
//     through the bind, 5 when none did.
//   prebind-sqpoll-orphan: before the bind, a second thread sets up an
//     SQPOLL ring and exits; the process keeps the ring (no task's io_uring
//     context lists it, only its SQPOLL thread shows it), and capset commits
//     new credentials; after the bind, the ring's thread runs a request.
//   access: access(W_OK) on a file with mode 0, with CAP_DAC_OVERRIDE and
//     CAP_DAC_READ_SEARCH out of the effective set: access() overrides to
//     credentials with the permitted set.
//   inline, async: a personality registered before dropping every
//     capability, in io_uring_enter or in an io-wq worker.
//   capset-async: no personality. An io-wq worker starts, then capset commits
//     new credentials with the same capabilities; the request runs in the
//     worker under the submitter's new credentials.
//   churn: a personality request linked behind a blocked pipe read; then
//     20000 new credentials, each used by a request under its own
//     personality; then the read is released by write(), and the linked
//     request runs from task_work on the return from write().
int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "inline";
	int own = !strncmp(mode, "prebind-", 8) || !strcmp(mode, "access") || !strcmp(mode, "postbind-ring");
	int id, res;

	if (!own)
		setup();
	if (own) {
		if (!strcmp(mode, "postbind-ring")) {
			int fd;

			wait_bound();
			setup();
			nop(0, IOSQE_ASYNC, 2);
			submit();
			reap(2);
			fd = open("/tmp/ringup", O_CREAT | O_WRONLY, 0644);
			if (fd < 0) fail("ringup");
			close(fd);
			while (access("/tmp/release", F_OK)) {
				if (ring >= 0 && !access("/tmp/close", F_OK)) {
					close_ring();
					ring = -1;
					fd = open("/tmp/closed", O_CREAT | O_WRONLY, 0644);
					if (fd < 0) fail("closed");
					close(fd);
				}
				usleep(10000);
			}
			return 0;
		} else if (!strcmp(mode, "prebind-thread")) {
			pthread_t th;

			// Created first: the thread shares the exec credentials.
			if (pthread_create(&th, NULL, raw_async_thread, NULL)) fail("pthread_create");
			caps(1);
			wait_bound();
			setup();
			nop(0, IOSQE_ASYNC, 2);
			submit();
			reap(2);
			__atomic_store_n(&thread_go, 1, __ATOMIC_RELEASE);
			pthread_join(th, NULL);
			res = thread_res;
		} else if (!strcmp(mode, "prebind-personality")) {
			setup();
			id = personality();
			caps(1);
			wait_bound();
			raw_socket(id, 0);
			submit();
			res = reap(1);
			if (res >= 0) { puts("raw socket created inline"); return 0; }
			res = linked_socket(id);
		} else if (!strcmp(mode, "prebind-async")) {
			setup();
			nop(0, IOSQE_ASYNC, 2);
			submit();
			reap(2);
			caps(1);
			wait_bound();
			raw_socket(0, IOSQE_ASYNC);
			submit();
			res = reap(1);
		} else if (!strcmp(mode, "prebind-closed")) {
			setup();
			nop(0, IOSQE_ASYNC, 2);
			submit();
			reap(2);
			close_ring();
			res = io_wq_worker();
			wait_bound();
			res = res && io_wq_worker();
			puts(res ? "an io-wq worker ran through the bind" : "no io-wq worker stayed after the ring closed");
			return res ? 0 : 5;
		} else if (!strcmp(mode, "prebind-sqpoll-orphan")) {
			pthread_t th;

			if (pthread_create(&th, NULL, sqpoll_thread, NULL)) fail("pthread_create");
			pthread_join(th, NULL);
			caps(1);
			wait_bound();
			raw_socket(0, 0);
			submit();
			res = reap(1);
		} else if (!strcmp(mode, "prebind-sqpoll")) {
			setup_flags(IORING_SETUP_SQPOLL);
			caps(1);
			wait_bound();
			raw_socket(0, 0);
			submit();
			res = reap(1);
		} else if (!strcmp(mode, "access")) {
			struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
			struct __user_cap_data_struct d[2];
			int fd;

			unlink("/tmp/access-file");
			fd = open("/tmp/access-file", O_CREAT | O_WRONLY, 0);
			if (fd < 0) fail("create");
			close(fd);
			if (syscall(__NR_capget, &h, d)) fail("capget");
			d[0].effective &= ~((1U << CAP_DAC_OVERRIDE) | (1U << CAP_DAC_READ_SEARCH));
			if (syscall(__NR_capset, &h, d)) fail("capset");
			if (!access("/tmp/access-file", W_OK)) { puts("access granted"); return 0; }
			printf("access: %s\n", strerror(errno));
			return errno == EACCES ? 1 : 2;
		} else {
			fprintf(stderr, "unknown mode %s\n", mode);
			return 3;
		}
	} else if (!strcmp(mode, "inline") || !strcmp(mode, "async")) {
		id = personality();
		caps(0);
		raw_socket(id, strcmp(mode, "async") ? 0 : IOSQE_ASYNC);
		submit();
		res = reap(1);
	} else if (!strcmp(mode, "capset-async")) {
		nop(0, IOSQE_ASYNC, 2);
		submit();
		reap(2);
		caps(1);
		raw_socket(0, IOSQE_ASYNC);
		submit();
		res = reap(1);
	} else if (!strcmp(mode, "churn")) {
		struct io_uring_sqe *e;
		int fds[2], i;
		char b;

		if (pipe(fds)) fail("pipe");
		id = personality();
		caps(1);
		e = sqe();
		e->opcode = IORING_OP_READ;
		e->fd = fds[0];
		e->addr = (unsigned long)&b;
		e->len = 1;
		e->flags = IOSQE_IO_LINK;
		e->user_data = 3;
		raw_socket(id, 0);
		submit();
		for (i = 0; i < 20000; i++) {
			int c;

			caps(1);
			c = personality();
			nop(c, 0, 4);
			submit();
			reap(4);
			if (syscall(__NR_io_uring_register, ring, IORING_UNREGISTER_PERSONALITY, NULL, c)) fail("unregister personality");
		}
		if (write(fds[1], "x", 1) != 1) fail("write");
		res = reap(1);
	} else {
		fprintf(stderr, "unknown mode %s\n", mode);
		return 3;
	}
	if (res >= 0) { puts("raw socket created"); return 0; }
	printf("socket: %s\n", strerror(-res));
	return res == -EPERM ? 1 : 2;
}
`

// ioUringModes are the helper's modes: a personality (inline in
// io_uring_enter, async in an io-wq worker); the submitter's own credentials
// after a capset in an io-wq worker (review scenario 1); and a personality
// request released from task_work after 20000 other personalities (review
// scenarios 2 and 3: no eviction, no syscall gate).
var ioUringModes = []string{"inline", "async", "capset-async", "churn"}

// TestIoUringPersonalityIsJudged: a capability check of an io_uring request
// runs under overridden credentials (a personality, or the submitter's
// credentials in a worker). The workload prepared them, so it must be judged:
// a raw socket is denied when a rule denies NET_RAW, in every mode.
func TestIoUringPersonalityIsJudged(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-raw", Action: "deny", Target: privpolicy.Target{Capability: []string{"NET_RAW"}}}
	doc := privpolicy.Document{Version: 1, Name: "io-uring", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.copyIoUringHelper(t)
	f.start(t, "privilege-io-uring", compiled, nil)
	for _, mode := range ioUringModes {
		if code, out := f.ioUring(t, mode); code != 0 {
			t.Fatalf("%s, unbound: the request must create the raw socket (exit %d): %s", mode, code, out)
		}
	}
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatal(err)
	}
	defer f.bindings.Unbind(f.container)
	for _, mode := range ioUringModes {
		if code, out := f.ioUring(t, mode); code != 1 {
			t.Fatalf("%s, bound: the NET_RAW deny must apply to the io_uring request (exit %d): %s", mode, code, out)
		}
	}
	if n, err := f.bindings.SlotFaults(0); err != nil || n != 0 {
		t.Fatalf("no slot fault: %d %v", n, err)
	}
	// churn recorded more than 20000 credentials; cred_free deleted them.
	f.waitCredRecordBelow(t, 1000)
}

// waitCredRecordBelow waits until the credential record holds fewer than n
// entries: freed credentials leave it (an RCU grace period after the free).
func (f *kernelFixture) waitCredRecordBelow(t *testing.T, n uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		used, _, err := f.bindings.CredRecordFill()
		if err != nil {
			t.Fatal(err)
		}
		if used < n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the credential record still holds %d entries; freed credentials must leave it", used)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ringModes open an io_uring ring before the bind (review 6 and 7).
var ringModes = []string{"prebind-personality", "prebind-async", "prebind-sqpoll", "prebind-sqpoll-orphan"}

// TestIoUringPrebindIsJudged: credentials prepared before the bind.
//   - A container whose tasks hold io_uring rings at the bind (a personality,
//     an io-wq worker, an SQPOLL ring, each opened before it) is refused a
//     Strict binding (ErrIoUringHeld, review 7): a request queued before the
//     bind could run later under credentials no task holds. Once the helper
//     is released and its ring is gone, the bind succeeds.
//   - Without a ring before the bind (prebind-thread), the bind walk records
//     the credentials the tasks hold, so a request a second thread sends
//     after the bind under its pre-bind credentials is judged.
func TestIoUringPrebindIsJudged(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-raw", Action: "deny", Target: privpolicy.Target{Capability: []string{"NET_RAW"}}}
	doc := privpolicy.Document{Version: 1, Name: "io-uring-prebind", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.copyIoUringHelper(t)
	f.start(t, "privilege-io-uring-prebind", compiled, nil)
	for _, mode := range append(append([]string(nil), ringModes...), "prebind-thread") {
		if code, out, _ := f.prebind(t, mode, false); code != 0 {
			t.Fatalf("%s, unbound: the request must create the raw socket (exit %d): %s", mode, code, out)
		}
	}
	for _, mode := range ringModes {
		code, out, bindErr := f.prebind(t, mode, true)
		if !errors.Is(bindErr, enforcement.ErrIoUringHeld) {
			t.Fatalf("%s: a Strict bind with a ring opened before it must be refused: %v", mode, bindErr)
		}
		if code != 0 {
			t.Fatalf("%s: the refused container is not bound (exit %d): %s", mode, code, out)
		}
		// The ring is gone with the helper: the bind succeeds now.
		if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
			t.Fatalf("%s: a bind after the ring closed: %v", mode, err)
		}
		if err := f.bindings.Unbind(f.container); err != nil {
			t.Fatal(err)
		}
	}
	if code, out, bindErr := f.prebind(t, "prebind-thread", true); bindErr != nil || code != 1 {
		t.Fatalf("prebind-thread: the NET_RAW deny must apply to the second thread's request (bind %v, exit %d): %s", bindErr, code, out)
	}
	if n, err := f.bindings.SlotFaults(0); err != nil || n != 0 {
		t.Fatalf("no slot fault: %d %v", n, err)
	}
}

// TestIoUringRingAuditBinds: an Audit binding with a ring opened before it
// binds and reports it (IoUringHeld); it never blocks.
func TestIoUringRingAuditBinds(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-raw", Action: "deny", Target: privpolicy.Target{Capability: []string{"NET_RAW"}}}
	doc := privpolicy.Document{Version: 1, Name: "io-uring-audit", Policy: privpolicy.Policy{Mode: "audit", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.copyIoUringHelper(t)
	f.start(t, "privilege-io-uring-audit", compiled, nil)
	code, out, bindErr := f.prebindHook(t, "prebind-async", func() error {
		if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
			return err
		}
		if !f.bindings.IoUringHeld(f.container.CgroupID) {
			return fmt.Errorf("an Audit binding with a ring must report it")
		}
		return nil
	})
	defer f.bindings.Unbind(f.container)
	if bindErr != nil || code != 0 {
		t.Fatalf("an Audit binding with a ring binds and never blocks (bind %v, exit %d): %s", bindErr, code, out)
	}
}

// TestIoUringClosedRingBindsStrict (review 9, F1): a task that ran async
// io_uring work and then closed its ring holds no ring: a Strict bind
// succeeds. On 6.12 its io-wq worker stays (io-wq is per task, and its last
// worker does not exit while the task runs), and the helper checks that it
// runs through the bind; 6.18 ends the worker with the ring (logged).
func TestIoUringClosedRingBindsStrict(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-raw", Action: "deny", Target: privpolicy.Target{Capability: []string{"NET_RAW"}}}
	doc := privpolicy.Document{Version: 1, Name: "io-uring-closed", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.copyIoUringHelper(t)
	f.start(t, "privilege-io-uring-closed", compiled, nil)
	code, out, bindErr := f.prebindHook(t, "prebind-closed", func() error {
		// The task's io_uring context drops the ring once the ring is
		// released (asynchronously), so a first bind can be refused.
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := f.bindings.Bind(enforcement.Binding{Container: f.container})
			if !errors.Is(err, enforcement.ErrIoUringHeld) || time.Now().After(deadline) {
				return err
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	defer f.bindings.Unbind(f.container)
	if bindErr != nil || (code != 0 && code != 5) {
		t.Fatalf("a task whose ring closed must not refuse a Strict bind (bind %v, exit %d): %s", bindErr, code, out)
	}
	if code == 5 {
		var u unix.Utsname
		_ = unix.Uname(&u)
		if strings.HasPrefix(unix.ByteSliceToString(u.Release[:]), "6.12.") {
			t.Fatalf("on 6.12 the io-wq worker must stay after its ring closed (the case under test): %s", out)
		}
		t.Logf("no io-wq worker stayed after the ring closed on %s", unix.ByteSliceToString(u.Release[:]))
	}
}

// TestIoUringRingAfterPurgeIsUnconfirmed (review 9, the purge path of review
// 8's N1 and N2): a restart with no live instance purges the record. A Strict
// binding whose task opened a ring after its bind is then unconfirmed
// (RingUnconfirmed: its slot health fails, so the policy reports
// ProtectionUnconfirmed), and its bind is refused (ErrIoUringHeld) while the
// ring is open; the adopted entry keeps protecting it. Once the task closes
// the ring (and keeps running), the bind succeeds and the binding is
// confirmed.
func TestIoUringRingAfterPurgeIsUnconfirmed(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-raw", Action: "deny", Target: privpolicy.Target{Capability: []string{"NET_RAW"}}}
	doc := privpolicy.Document{Version: 1, Name: "ring-after-purge", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.copyIoUringHelper(t)
	f.start(t, "privilege-ring-purge-1", compiled, nil)
	if err := f.exec("rm", "-f", "/tmp/ready", "/tmp/bound", "/tmp/ringup", "/tmp/release", "/tmp/close", "/tmp/closed"); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd := exec.CommandContext(f.ctx, "docker", "exec", f.id, "/io-uring-personality", "postbind-ring")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// done closes when the helper exits (Wait in its own goroutine, so a
	// check can tell a running helper from an exited one).
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	released := false
	release := func() {
		if !released {
			released = true
			f.exec("touch", "/tmp/release")
			<-done
		}
	}
	defer release()
	wait := func(file string) {
		deadline := time.Now().Add(20 * time.Second)
		for f.exec("sh", "-c", "test -f "+file) != nil {
			if time.Now().After(deadline) {
				t.Fatalf("no %s: %s", file, out.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	wait("/tmp/ready")
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatalf("no ring before the bind: %v", err)
	}
	if err := f.exec("touch", "/tmp/bound"); err != nil {
		t.Fatal(err)
	}
	wait("/tmp/ringup")
	f.stop() // no live instance: the next start purges the record
	second := &kernelFixture{ctx: f.ctx, id: f.id, container: f.container}
	second.start(t, "privilege-ring-purge-2", compiled, nil)
	if n := second.bindings.RingUnconfirmed(0); n != 1 {
		t.Fatalf("after the purge, the Strict binding with a ring must be unconfirmed: %d", n)
	}
	if err := second.bindings.Bind(enforcement.Binding{Container: f.container}); !errors.Is(err, enforcement.ErrIoUringHeld) {
		t.Fatalf("the bind must be refused while the ring is open: %v", err)
	}
	if n := second.bindings.RingUnconfirmed(0); n != 1 {
		t.Fatalf("a refused bind keeps the binding unconfirmed: %d", n)
	}
	if n := second.bindings.AdoptedBindings()[0]; n != 1 {
		t.Fatalf("the adopted Strict entry must stay after the refusal: %d", n)
	}
	if err := f.exec("touch", "/tmp/close"); err != nil {
		t.Fatal(err)
	}
	wait("/tmp/closed")
	// The task's io_uring context drops the ring once it is released
	// (asynchronously), so a first bind can still be refused.
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := second.bindings.Bind(enforcement.Binding{Container: f.container})
		if err == nil {
			break
		}
		if !errors.Is(err, enforcement.ErrIoUringHeld) || time.Now().After(deadline) {
			t.Fatalf("the bind must succeed once the ring is closed (the task still runs): %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer second.bindings.Unbind(f.container)
	select {
	case <-done:
		t.Fatalf("the task must still run when its binding is confirmed: %s", out.String())
	default:
	}
	if n := second.bindings.RingUnconfirmed(0); n != 0 {
		t.Fatalf("the binding must be confirmed once the ring is closed: %d", n)
	}
}

// prebind starts the helper in a prebind mode, waits until it is ready, binds
// the container when bind is set, then releases the helper and returns its
// exit code and the bind's error. The binding is removed before it returns.
func (f *kernelFixture) prebind(t *testing.T, mode string, bind bool) (int, string, error) {
	t.Helper()
	var hook func() error
	if bind {
		hook = func() error { return f.bindings.Bind(enforcement.Binding{Container: f.container}) }
	}
	code, out, err := f.prebindHook(t, mode, hook)
	if bind && err == nil {
		f.bindings.Unbind(f.container)
	}
	return code, out, err
}

// prebindHook runs hook (when not nil) while the helper waits in a prebind
// mode, then releases the helper.
func (f *kernelFixture) prebindHook(t *testing.T, mode string, hook func() error) (int, string, error) {
	t.Helper()
	if err := f.exec("rm", "-f", "/tmp/ready", "/tmp/bound"); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd := exec.CommandContext(f.ctx, "docker", "exec", f.id, "/io-uring-personality", mode)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for f.exec("sh", "-c", "test -f /tmp/ready") != nil {
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("%s: the helper is not ready: %s", mode, out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	var hookErr error
	if hook != nil {
		hookErr = hook()
	}
	if err := f.exec("touch", "/tmp/bound"); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), hookErr
	case errors.As(err, &exit):
		return exit.ExitCode(), out.String(), hookErr
	}
	t.Fatalf("run the helper: %v", err)
	return -1, "", nil
}

// TestAccessOverrideIsJudged: access() overrides to credentials it prepares
// (the effective set becomes the permitted set). The workload prepared them,
// so they are judged outside io_uring too: with CAP_DAC_OVERRIDE out of the
// effective set but permitted, access(W_OK) on a mode-0 file is refused when
// a rule denies DAC_OVERRIDE.
func TestAccessOverrideIsJudged(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-dac-override", Action: "deny", Target: privpolicy.Target{Capability: []string{"DAC_OVERRIDE"}}}
	doc := privpolicy.Document{Version: 1, Name: "access-override", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.copyIoUringHelper(t)
	f.start(t, "privilege-access-override", compiled, nil)
	if code, out := f.ioUring(t, "access"); code != 0 {
		t.Fatalf("unbound: access must be granted (exit %d): %s", code, out)
	}
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatal(err)
	}
	defer f.bindings.Unbind(f.container)
	if code, out := f.ioUring(t, "access"); code != 1 {
		t.Fatalf("bound: the DAC_OVERRIDE deny must apply to access() under its override (exit %d): %s", code, out)
	}
}

// TestOverlayCopyUpWithDACDeny: overlayfs overrides to the mounter's
// credentials and then prepares copies of them in the container's task: for a
// copy-up when an LSM has a copy-up hook (SELinux), and for every create
// (ovl_setup_cred_for_create). Those copies are not the workload's. With
// DAC_OVERRIDE and DAC_READ_SEARCH denied, a write that copies an image
// directory up (SELinux only) and a create over a whiteout (any LSM: it looks
// up overlay's mode-0 work directory under the create's copy) must work. The
// workload's own DAC_OVERRIDE stays denied. Needs an overlay2 root file system
// (Docker's default).
func TestOverlayCopyUpWithDACDeny(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-dac", Action: "deny", Target: privpolicy.Target{Capability: []string{"DAC_OVERRIDE", "DAC_READ_SEARCH"}}}
	doc := privpolicy.Document{Version: 1, Name: "overlay-copy-up", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	upper, err := exec.Command("docker", "inspect", "-f", "{{.GraphDriver.Name}} {{.GraphDriver.Data.UpperDir}}", f.id).Output()
	if err != nil {
		t.Fatal(err)
	}
	driver, upperDir, _ := strings.Cut(strings.TrimSpace(string(upper)), " ")
	if driver != "overlay2" || upperDir == "" {
		t.Skipf("root file system is %q, not overlay2", driver)
	}
	lsm, _ := os.ReadFile("/sys/kernel/security/lsm")
	selinux := slices.Contains(strings.Split(strings.TrimSpace(string(lsm)), ","), "selinux")
	// Image entries of /usr/share that are not in the upper layer yet.
	lower := func(findArgs ...string) []string {
		out, err := exec.Command("docker", append([]string{"exec", f.id, "find", "/usr/share", "-mindepth", "1"}, findArgs...)...).Output()
		if err != nil {
			t.Fatal(err)
		}
		var paths []string
		for _, p := range strings.Fields(string(out)) {
			if _, err := os.Lstat(filepath.Join(upperDir, filepath.Dir(p))); errors.Is(err, os.ErrNotExist) {
				paths = append(paths, p)
			}
		}
		return paths
	}
	dirs, files := lower("-maxdepth", "1", "-type", "d"), lower("-mindepth", "2", "-maxdepth", "2", "-type", "f")
	if len(files) == 0 || selinux && len(dirs) < 2 {
		t.Skip("the image has too few /usr/share entries outside the upper layer")
	}
	sh := func(script string) error {
		out, err := exec.Command("docker", "exec", f.id, "sh", "-c", script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}
	settled := func() []string {
		time.Sleep(500 * time.Millisecond)
		f.mu.Lock()
		defer f.mu.Unlock()
		return append([]string(nil), f.events...)
	}
	// The whiteout case alone: its directory is copied up before the bind,
	// so the bound part has no copy-up, only the create over the whiteout.
	file := files[0]
	if err := sh("touch " + filepath.Dir(file) + "/.sbx-upper"); err != nil {
		t.Fatal(err)
	}
	f.start(t, "privilege-overlay-copy-up", compiled, nil)
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatal(err)
	}
	defer f.bindings.Unbind(f.container)
	if err := sh("rm " + file + " && echo hi > " + file); err != nil {
		t.Fatalf("a create over the whiteout of %s must work under a DAC deny: %v (verdicts %v)", file, err, settled())
	}
	if st, err := os.Lstat(filepath.Join(upperDir, file)); err != nil || !st.Mode().IsRegular() {
		t.Fatalf("%s is not a new upper file, so the test did not reach the create over the whiteout: %v", file, err)
	}
	if selinux {
		// Not the whiteout case's directory (copied up already).
		dir := dirs[0]
		if dir == filepath.Dir(file) {
			dir = dirs[1]
		}
		if err := sh("echo hi > " + dir + "/sbx-copy-up"); err != nil {
			t.Fatalf("a write that copies %s up must work under a DAC deny: %v (verdicts %v)", dir, err, settled())
		}
		if _, err := os.Lstat(filepath.Join(upperDir, dir)); err != nil {
			t.Fatalf("%s was not copied up, so the test did not reach the copy-up: %v", dir, err)
		}
	} else {
		t.Log("no SELinux: only the create over a whiteout reaches the bug")
	}
	if events := settled(); len(events) != 0 {
		t.Fatalf("the overlay operations must make no verdict: %v", events)
	}
	// The workload's own DAC_OVERRIDE: root reads a mode-0 file.
	if err := sh("rm -f /tmp/sbx-dac-own && : > /tmp/sbx-dac-own && chmod 000 /tmp/sbx-dac-own"); err != nil {
		t.Fatalf("create the mode-0 file: %v", err)
	}
	if sh("cat /tmp/sbx-dac-own") == nil {
		t.Fatal("the workload's own DAC_OVERRIDE must stay denied")
	}
	if len(settled()) == 0 {
		t.Fatal("the denied read must make a verdict")
	}
}

// TestFloodLeavesSummary: past the report limit (100 per CPU per second) a
// deny has no event, so one real attempt hidden in a flood of cheap denied
// actions left only a counter. Each lost deny is now counted in the summary
// map under its generation, slot, rule, hook, mode and cgroup, with the
// first and last task. One process, pinned to one CPU, makes 5000 denied
// unshare(CLONE_NEWNS), one denied setuid (another rule: CAP_SETUID), and
// 5000 more. The flood's rule has a summary of its lost denies, and the
// hidden deny is either a summary record of its own rule or (when a report
// window opened right then) an event: exactly one of the two.
func TestFloodLeavesSummary(t *testing.T) {
	f := newKernelFixture(t)
	flood := privpolicy.Rule{Name: "no-newns", Action: "deny", Target: privpolicy.Target{Syscall: []string{"unshare"}, Flags: []string{"CLONE_NEWNS"}}}
	hidden := privpolicy.Rule{Name: "no-setuid", Action: "deny", Target: privpolicy.Target{Capability: []string{"SETUID"}}}
	doc := privpolicy.Document{Version: 1, Name: "flood-summary", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{flood, hidden}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	idOf := func(name string) uint32 {
		for i, n := range compiled.RuleNames {
			if n == name || strings.HasSuffix(n, "/"+name) {
				return uint32(i)
			}
		}
		t.Fatalf("no rule %s in %v", name, compiled.RuleNames)
		return 0
	}
	f.start(t, "privilege-flood-summary", compiled, nil)
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatal(err)
	}
	defer f.bindings.Unbind(f.container)
	if _, err := f.bindings.DrainVerdictSummaries(1024); err != nil {
		t.Fatalf("the summary map must be there: %v", err)
	}
	// unshare is syscall 272 and setuid 105 on x86_64; each call fails with
	// EPERM. The process runs on the first CPU of its allowed list.
	script := `for (1..5000) { syscall(272, 0x20000) } syscall(105, 4242); for (1..5000) { syscall(272, 0x20000) }`
	cmd := `cpu=$(awk '/Cpus_allowed_list/{print $2}' /proc/self/status | cut -d, -f1 | cut -d- -f1); ` +
		`if command -v taskset >/dev/null; then exec taskset -c "$cpu" perl -e '` + script + `'; fi; exec perl -e '` + script + `'`
	if out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, "sh", "-c", cmd).CombinedOutput(); err != nil {
		t.Fatalf("flood: %v %s", err, out)
	}
	summaries, err := f.bindings.DrainVerdictSummaries(1024)
	if err != nil {
		t.Fatal(err)
	}
	var floodCount, hiddenCount uint64
	for _, s := range summaries {
		t.Logf("summary %+v", s)
		if s.FirstComm != "perl" || !s.Enforce || s.CgroupID != f.container.CgroupID {
			continue
		}
		switch s.RuleID {
		case idOf("no-newns"):
			floodCount += s.Count
		case idOf("no-setuid"):
			hiddenCount += s.Count
		}
	}
	time.Sleep(500 * time.Millisecond) // the events of the reported denies
	hiddenEvents := 0
	f.mu.Lock()
	for _, e := range f.events {
		if strings.Contains(e, "cap=7 ") && strings.HasSuffix(e, " perl") {
			hiddenEvents++
		}
	}
	f.mu.Unlock()
	// At most 100 reports per second on that CPU have an event.
	if floodCount < 9000 {
		t.Fatalf("the flood's lost denies must be summarized: %d of 10000 (events %d)", floodCount, f.verdicts.Load())
	}
	if hiddenCount+uint64(hiddenEvents) != 1 {
		t.Fatalf("the hidden deny must leave exactly one trace: %d summarized, %d events", hiddenCount, hiddenEvents)
	}
	if hiddenCount != 1 {
		t.Logf("the hidden deny was reported in an event (a report window opened right then)")
	}
	if again, _ := f.bindings.DrainVerdictSummaries(1024); len(again) != 0 {
		t.Fatalf("a drain deletes what it read: %+v", again)
	}
}

// TestCredRecordProbeRefusesWithoutFree: with cred_free deleting nothing (as
// on a kernel without an LSM that has a cred blob), the start probe sees its
// freed credentials stay in the record and refuses the instance.
func TestCredRecordProbeRefusesWithoutFree(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-modules", Action: "deny", Target: privpolicy.Target{Syscall: []string{"init_module"}}}
	doc := privpolicy.Document{Version: 1, Name: "cred-probe", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = f.startConfig(t, "privilege-cred-probe", Config{Policy: compiled, FaultInjection: true}, map[string]string{"cred-forget-fail": "1"})
	if err == nil || !strings.Contains(err.Error(), "freed credentials stay") {
		t.Fatalf("start = %v, want the probe to refuse it", err)
	}
}

// TestCredRecordPurgedOnColdStart: a start with no other instance purges the
// pinned record (it may hold freed addresses); a start next to a live
// instance keeps it.
func TestCredRecordPurgedOnColdStart(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-modules", Action: "deny", Target: privpolicy.Target{Syscall: []string{"init_module"}}}
	doc := privpolicy.Document{Version: 1, Name: "cred-purge", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, "privilege-cred-purge-1", compiled, nil)
	stopFirst := f.stop
	record, err := ebpf.LoadPinnedMap(filepath.Join(enforcement.PinRoot, MapPrefix+"creds"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Close()
	stale := uint64(0xdead0000)
	if err := record.Put(stale, uint64(1)); err != nil {
		t.Fatal(err)
	}
	var cgroup uint64
	second := &kernelFixture{ctx: f.ctx, id: f.id, container: f.container}
	second.start(t, "privilege-cred-purge-2", compiled, nil)
	if err := record.Lookup(stale, &cgroup); err != nil {
		t.Fatalf("a start next to a live instance must keep the record: %v", err)
	}
	second.stop()
	stopFirst()
	// Only the record's pins stay, as after an uninstall that kept them (the
	// slot state of the stopped instances would hold their slots in
	// quarantine).
	pins, err := filepath.Glob(filepath.Join(enforcement.PinRoot, MapPrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pins {
		if !strings.HasPrefix(filepath.Base(p), MapPrefix+"cred") {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}
	}
	third := &kernelFixture{ctx: f.ctx, id: f.id, container: f.container}
	third.start(t, "privilege-cred-purge-3", compiled, nil)
	if err := record.Lookup(stale, &cgroup); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("a start with no other instance must purge the record: %v", err)
	}
}

const credFillHelper = `#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

// Commits new credentials (capset with the same capabilities) and keeps each
// alive with an open file, until a capset fails; then writes the count and
// the errno to argv[1] and waits.
int main(int argc, char **argv)
{
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2];
	int n, err = 0;
	FILE *out;

	if (syscall(__NR_capget, &h, d)) return 2;
	for (n = 0; n < 900; n++) {
		if (syscall(__NR_capset, &h, d)) { err = errno; break; }
		if (open("/dev/null", O_RDONLY) < 0) return 2;
	}
	out = fopen(argv[1], "w");
	if (!out) return 2;
	fprintf(out, "%d %d\n", n, err);
	fclose(out);
	pause();
	return 0;
}
`

// hostCgroup makes an empty cgroup on the host for a test binding.
func hostCgroup(t *testing.T, name string) ContainerIdentity {
	t.Helper()
	path := fmt.Sprintf("/privilege-cred-%s-%d", name, os.Getpid())
	if err := os.Mkdir(filepath.Join("/sys/fs/cgroup", path), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(filepath.Join("/sys/fs/cgroup", path)) })
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", path), &st); err != nil {
		t.Fatal(err)
	}
	return ContainerIdentity{Runtime: "test", ID: "cred-" + name, CgroupID: st.Ino, CgroupPath: path}
}

// TestCredRecordQuotaPerBinding: a binding that fills its quota of the
// credential record is refused new credentials (ENOMEM) and counts a slot
// fault; another Strict binding on the node keeps working. When the filler
// exits, its credentials leave the record.
func TestCredRecordQuotaPerBinding(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-modules", Action: "deny", Target: privpolicy.Target{Syscall: []string{"init_module"}}}
	doc := privpolicy.Document{Version: 1, Name: "cred-quota", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	const quota = 64
	if err := f.startConfig(t, "privilege-cred-quota", Config{Policy: compiled, CredQuota: quota}, nil); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	filler := filepath.Join(dir, "cred-fill")
	if err := os.WriteFile(filler+".c", []byte(credFillHelper), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O2", "-o", filler, filler+".c").CombinedOutput(); err != nil {
		t.Fatalf("build the filler: %v: %s", err, out)
	}
	a, b := hostCgroup(t, "a"), hostCgroup(t, "b")
	for _, c := range []ContainerIdentity{a, b} {
		if err := f.bindings.Bind(enforcement.Binding{Container: c}); err != nil {
			t.Fatal(err)
		}
		defer f.bindings.Unbind(c)
	}
	result := filepath.Join(dir, "filled")
	fill := exec.Command("sh", "-c", fmt.Sprintf("echo $$ > /sys/fs/cgroup%s/cgroup.procs && exec %s %s", a.CgroupPath, filler, result))
	if err := fill.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { fill.Process.Kill(); fill.Wait() }()
	var data []byte
	deadline := time.Now().Add(20 * time.Second)
	for len(data) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the filler did not finish")
		}
		time.Sleep(50 * time.Millisecond)
		data, _ = os.ReadFile(result)
	}
	var n, errno int
	if _, err := fmt.Sscan(string(data), &n, &errno); err != nil {
		t.Fatal(err)
	}
	if errno != int(unix.ENOMEM) || n > quota {
		t.Fatalf("binding a: %d credentials, then errno %d; want ENOMEM at its quota of %d", n, errno, quota)
	}
	if faults, err := f.bindings.SlotFaults(0); err != nil || faults == 0 {
		t.Fatalf("the refusal must count a slot fault: %d %v", faults, err)
	}
	if out, err := exec.Command("sh", "-c", fmt.Sprintf("echo $$ > /sys/fs/cgroup%s/cgroup.procs && exec sh -c 'true & wait'", b.CgroupPath)).CombinedOutput(); err != nil {
		t.Fatalf("binding b must keep working while binding a is over its quota: %v %s", err, out)
	}
	if used, _, err := f.bindings.CredRecordFill(); err != nil || used < quota-8 {
		t.Fatalf("record fill = %d %v, want about the quota", used, err)
	}
	fill.Process.Kill()
	fill.Wait()
	f.waitCredRecordBelow(t, 16)
}

// TestCredRecordFailureFailsClosed fails every record of prepared
// credentials, as a full record does. A Strict binding refuses the
// preparation (the exec into the container fails) and counts a slot fault;
// an Audit binding lets it run with no slot fault.
func TestCredRecordFailureFailsClosed(t *testing.T) {
	for _, mode := range []string{"enforce", "audit"} {
		t.Run(mode, func(t *testing.T) {
			f := newKernelFixture(t)
			rule := privpolicy.Rule{Name: "no-modules", Action: "deny", Target: privpolicy.Target{Syscall: []string{"init_module"}}}
			doc := privpolicy.Document{Version: 1, Name: "cred-record-" + mode, Policy: privpolicy.Policy{Mode: mode, Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
			compiled, err := privpolicy.CompileKernel(doc, 1)
			if err != nil {
				t.Fatal(err)
			}
			f.start(t, "privilege-cred-record-"+mode, compiled, map[string]string{"cred-record-fail": "1"})
			if err := f.exec("true"); err != nil {
				t.Fatalf("an unbound container must not be judged: %v", err)
			}
			if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
				t.Fatal(err)
			}
			defer f.bindings.Unbind(f.container)
			err = f.exec("true")
			faults, ferr := f.bindings.SlotFaults(0)
			if ferr != nil {
				t.Fatal(ferr)
			}
			switch mode {
			case "enforce":
				if err == nil {
					t.Fatal("a Strict binding must refuse credentials it cannot record")
				}
				if faults == 0 {
					t.Fatal("the refusal must count a slot fault")
				}
			case "audit":
				if err != nil {
					t.Fatalf("an Audit binding must not block: %v", err)
				}
				if faults != 0 {
					t.Fatalf("Audit counts no slot fault: %d", faults)
				}
			}
		})
	}
}

// copyIoUringHelper builds the io_uring helper and copies it into the
// container.
func (f *kernelFixture) copyIoUringHelper(t *testing.T) {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "io-uring-personality")
	if err := os.WriteFile(helper+".c", []byte(ioUringPersonalityHelper), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O2", "-static", "-pthread", "-o", helper, helper+".c").CombinedOutput(); err != nil {
		t.Fatalf("build the helper: %v: %s", err, out)
	}
	if out, err := exec.CommandContext(f.ctx, "docker", "cp", helper, f.id+":/io-uring-personality").CombinedOutput(); err != nil {
		t.Fatalf("copy the helper: %v: %s", err, out)
	}
}

// ioUring runs the helper in the container and returns its exit code.
func (f *kernelFixture) ioUring(t *testing.T, mode string) (int, string) {
	t.Helper()
	out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, "/io-uring-personality", mode).CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exit):
		return exit.ExitCode(), string(out)
	}
	t.Fatalf("run the helper: %v", err)
	return -1, ""
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
			f.start(t, "privilege-headers-"+mode, compiled, map[string]string{"policy-fail-headers": "1"})
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
				// The fork result is read from busybox sh's error text.
				// /bin/sh must be busybox too (the same file: a hard link in
				// the busybox image, a symlink in alpine): a debian image
				// with busybox installed still has dash as /bin/sh.
				if out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, "sh", "-c", `busybox true && [ /bin/sh -ef "$(command -v busybox)" ]`).CombinedOutput(); err != nil {
					t.Skipf("needs a busybox container whose /bin/sh is busybox (the fork errors are busybox sh's text): %v %s", err, out)
				}
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
				f.start(t, "privilege-coexist", compiled, map[string]string{"arming-fail-fork-marks": "1"})
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
					// Its own state: the first instance keeps its maps, so
					// it does not judge the container bound here.
					if err := enforcement.RemovePinnedMaps(MapPrefix); err != nil {
						t.Fatal(err)
					}
					f.start(t, "privilege-coexist-2", compiled, map[string]string{"arming-fail-fork-marks": "1"})
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
	// A hook gets no PATH from the runtime, and the shell's default may miss
	// the sbin directories (AL2023 keeps chroot in /usr/sbin): without one, the
	// hook never calls chroot.
	hook := func(path string) []map[string]any {
		return []map[string]any{{"path": path, "args": []string{"sh", "-c", "PATH=/usr/sbin:/usr/bin:/sbin:/bin; chroot / true; true"}}}
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

// fillIn runs the filler (credFillHelper) in a host cgroup and returns how
// many credentials it kept and the errno that stopped it. stop ends it.
func fillIn(t *testing.T, filler, dir string, c ContainerIdentity) (n, errno int, stop func()) {
	t.Helper()
	result := filepath.Join(dir, "filled-"+c.ID)
	fill := exec.Command("sh", "-c", fmt.Sprintf("echo $$ > /sys/fs/cgroup%s/cgroup.procs && exec %s %s", c.CgroupPath, filler, result))
	if err := fill.Start(); err != nil {
		t.Fatal(err)
	}
	stop = func() { fill.Process.Kill(); fill.Wait() }
	var data []byte
	deadline := time.Now().Add(20 * time.Second)
	for len(data) == 0 {
		if time.Now().After(deadline) {
			stop()
			t.Fatal("the filler did not finish")
		}
		time.Sleep(50 * time.Millisecond)
		data, _ = os.ReadFile(result)
	}
	if _, err := fmt.Sscan(string(data), &n, &errno); err != nil {
		stop()
		t.Fatal(err)
	}
	return n, errno, stop
}

// TestCredRecordShareUnderPressure (reviews 7 and 8): the quotas add up to
// more than the record can give. A test record of 1200 entries with a
// pressure level of 900 and a quota of 75: 12 bindings fill their quotas up
// to the pressure level, 38 more are each refused at their share of the last
// quarter ((1200-900)/51), the record keeps room, and the 51st binding still
// forks and execs.
func TestCredRecordShareUnderPressure(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-modules", Action: "deny", Target: privpolicy.Target{Syscall: []string{"init_module"}}}
	doc := privpolicy.Document{Version: 1, Name: "cred-share", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	const quota, pressure, size, full, more = 75, 900, 1200, 12, 38
	if err := f.startConfig(t, "privilege-cred-share", Config{Policy: compiled, CredQuota: quota, CredPressure: pressure, CredSize: size}, nil); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	filler := filepath.Join(dir, "cred-fill")
	if err := os.WriteFile(filler+".c", []byte(credFillHelper), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O2", "-o", filler, filler+".c").CombinedOutput(); err != nil {
		t.Fatalf("build the filler: %v: %s", err, out)
	}
	var ids []ContainerIdentity
	for i := 0; i < full+more+1; i++ {
		id := hostCgroup(t, fmt.Sprint("s", i))
		if err := f.bindings.Bind(enforcement.Binding{Container: id}); err != nil {
			t.Fatal(err)
		}
		defer f.bindings.Unbind(id)
		ids = append(ids, id)
	}
	share := (size - pressure) / len(ids)
	for i, id := range ids[:full+more] {
		n, errno, stop := fillIn(t, filler, dir, id)
		defer stop()
		switch {
		case errno != int(unix.ENOMEM):
			t.Fatalf("binding %d: errno %d after %d credentials, want ENOMEM", i, errno, n)
		case i < full && (n > quota || n < quota-5):
			t.Fatalf("binding %d: %d credentials, want its quota %d (the record is under the pressure level)", i, n, quota)
		case i >= full && n > share:
			t.Fatalf("binding %d: %d credentials past the pressure level, want at most its share %d", i, n, share)
		}
	}
	if used, _, err := f.bindings.CredRecordFill(); err != nil || used >= size {
		t.Fatalf("record fill %d %v: the reserve must hold below %d", used, err, size)
	}
	last := ids[len(ids)-1]
	if out, err := exec.Command("sh", "-c", fmt.Sprintf("echo $$ > /sys/fs/cgroup%s/cgroup.procs && exec sh -c 'true & wait'", last.CgroupPath)).CombinedOutput(); err != nil {
		t.Fatalf("a binding under its share must keep working: %v %s", err, out)
	}
}

// TestIoUringAfterBindSurvivesReplacement (review 8, N1): a container that
// opens its ring after its Strict bind keeps Strict when a replacement
// instance (next to the live one, so the record is not purged) takes its
// adopted binding over.
func TestIoUringAfterBindSurvivesReplacement(t *testing.T) {
	f := newKernelFixture(t)
	rule := privpolicy.Rule{Name: "no-raw", Action: "deny", Target: privpolicy.Target{Capability: []string{"NET_RAW"}}}
	doc := privpolicy.Document{Version: 1, Name: "ring-after-bind", Policy: privpolicy.Policy{Mode: "enforce", Privilege: privpolicy.Section{Default: "allow", Rules: []privpolicy.Rule{rule}}}}
	compiled, err := privpolicy.CompileKernel(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.copyIoUringHelper(t)
	f.start(t, "privilege-ring-after-1", compiled, nil)
	if err := f.exec("rm", "-f", "/tmp/ready", "/tmp/bound", "/tmp/ringup", "/tmp/release", "/tmp/close", "/tmp/closed"); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd := exec.CommandContext(f.ctx, "docker", "exec", f.id, "/io-uring-personality", "postbind-ring")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { f.exec("touch", "/tmp/release"); cmd.Wait() }()
	wait := func(file string) {
		deadline := time.Now().Add(20 * time.Second)
		for f.exec("sh", "-c", "test -f "+file) != nil {
			if time.Now().After(deadline) {
				t.Fatalf("no %s: %s", file, out.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	wait("/tmp/ready")
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatalf("no ring before the bind: %v", err)
	}
	if err := f.exec("touch", "/tmp/bound"); err != nil {
		t.Fatal(err)
	}
	wait("/tmp/ringup")
	second := &kernelFixture{ctx: f.ctx, id: f.id, container: f.container}
	second.start(t, "privilege-ring-after-2", compiled, nil)
	if err := second.bindings.Bind(enforcement.Binding{Container: f.container}); err != nil {
		t.Fatalf("a ring opened after the Strict bind must not refuse the replacement's bind: %v", err)
	}
	defer second.bindings.Unbind(f.container)
}
