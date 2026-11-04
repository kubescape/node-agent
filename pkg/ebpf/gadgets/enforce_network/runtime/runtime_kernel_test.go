//go:build linux && network_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

// Opt-in test of the gadget with Inspektor Gadget alone: it parses the example
// policy file, starts the gadget from an OCI archive and binds Docker
// containers through this package's operator. The same case matrix runs
// against each program tier: TestGadgetWithInspektorGadgetAlone (BPF LSM, the
// default) and TestGadgetCgroupTier (cgroup sock_addr; skipped when the linked
// Inspektor Gadget cannot attach cgroup programs). Requires root, BPF LSM for
// the LSM tier, cgroup v2, and disposable containers with python3:
//
//	NETWORK_KERNEL_TEST=1
//	NETWORK_IMAGE_ARCHIVE       OCI archive from `ig image export`
//	NETWORK_IMAGE               image name in the archive
//	NETWORK_CONTAINER_ID        full ID of the container to bind
//	NETWORK_CGROUP_PATH         its cgroup v2 path, for example /system.slice/docker-<id>.scope
//	NETWORK_OTHER_CONTAINER_ID  a container that is never bound
//
// Optional, for `docker run` under a default deny: a cgroup that holds new
// containers (bound before they start) and the image to run.
//
//	NETWORK_PARENT_CGROUP       for example /netgadget.slice
//	NETWORK_CGROUP_PARENT       the docker --cgroup-parent value, for example netgadget.slice
//	NETWORK_RUN_IMAGE           an image with python3
//
// Optional: NETWORK_UNUSED_TIER_UNLOADED=1 also requires that no program of
// the unused tier is loaded (see checkLoaded).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
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
	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
)

// probe runs one network call and prints OK, timeout or the errno name.
const probe = `
import ctypes, errno, socket, struct, sys
kind, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
libc = ctypes.CDLL(None, use_errno=True)
def sin(family):
    return struct.pack("=H", family) + struct.pack("!H", port) + socket.inet_aton(host) + bytes(8)
class iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
class msghdr(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint32), ("iov", ctypes.POINTER(iovec)),
                ("iovlen", ctypes.c_size_t), ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
                ("flags", ctypes.c_int)]
class mmsghdr(ctypes.Structure):
    _fields_ = [("hdr", msghdr), ("len", ctypes.c_uint)]
def sendmmsg(s, addrs):
    data = ctypes.create_string_buffer(b"x")
    iov = iovec(ctypes.cast(data, ctypes.c_void_p), 1)
    names = [ctypes.create_string_buffer(a, len(a)) for a in addrs]
    msgs = (mmsghdr * len(addrs))()
    for i, n in enumerate(names):
        msgs[i].hdr = msghdr(ctypes.cast(n, ctypes.c_void_p), len(addrs[i]), ctypes.pointer(iov), 1, None, 0, 0)
    n = libc.sendmmsg(s.fileno(), msgs, len(addrs), 0)
    if n < 0:
        raise OSError(ctypes.get_errno(), "sendmmsg")
    return n
def raw_sendto(s, sa):
    if libc.sendto(s.fileno(), b"x", 1, 0, sa, len(sa)) < 0:
        raise OSError(ctypes.get_errno(), "sendto")
v4, v6, tcp, udp = socket.AF_INET, socket.AF_INET6, socket.SOCK_STREAM, socket.SOCK_DGRAM
try:
    if kind == "tcp4" or kind == "tcp6":
        s = socket.socket(v4 if kind == "tcp4" else v6, tcp)
        s.settimeout(1)
        s.connect((host, port))
    elif kind == "udp-connect":
        socket.socket(v4, udp).connect((host, port))
    elif kind == "udp4-sendto":
        socket.socket(v4, udp).sendto(b"x", (host, port))
    elif kind == "udp6-sendto":
        socket.socket(v6, udp).sendto(b"x", (host, port))
    elif kind == "udp6-sendto-sockaddr_in":
        raw_sendto(socket.socket(v6, udp), sin(socket.AF_INET))
    elif kind == "udp4-sendto-unspec":
        raw_sendto(socket.socket(v4, udp), sin(socket.AF_UNSPEC))
    elif kind == "tcp4-fastopen":
        s = socket.socket(v4, tcp)
        s.settimeout(1)
        s.sendto(b"x", socket.MSG_FASTOPEN, (host, port))
    elif kind == "tcp4-connected-sendto":
        # TCP ignores the address of a send on a connected socket.
        l = socket.socket(v4, tcp)
        l.bind(("127.0.0.1", 0))
        l.listen(1)
        s = socket.socket(v4, tcp)
        s.connect(l.getsockname())
        s.sendto(b"x", (host, port))
    elif kind == "tcp4-connected-fastopen":
        # MSG_FASTOPEN on a connected socket: the kernel alone fails it
        # with EISCONN.
        l = socket.socket(v4, tcp)
        l.bind(("127.0.0.1", 0))
        l.listen(1)
        s = socket.socket(v4, tcp)
        s.connect(l.getsockname())
        s.sendto(b"x", socket.MSG_FASTOPEN, (host, port))
    elif kind == "raw6-sendto-unspec":
        sa = struct.pack("=HHI", 0, 0, 0) + socket.inet_pton(v6, host) + bytes(4)
        raw_sendto(socket.socket(v6, socket.SOCK_RAW, socket.IPPROTO_UDP), sa)
    elif kind == "udp4-sendmmsg":
        # An allowed message (loopback), then the destination: prints the
        # number of messages sent when it is not every message.
        ok = struct.pack("=H", v4) + struct.pack("!H", 9) + socket.inet_aton("127.0.0.1") + bytes(8)
        n = sendmmsg(socket.socket(v4, udp), [ok, sin(v4)])
        if n != 2:
            print("sent %d" % n)
            sys.exit(0)
    elif kind == "udp-connected-sendto":
        s = socket.socket(v4, udp)
        s.connect(("192.0.2.7", port))
        s.sendto(b"x", (host, port))
    print("OK")
except socket.timeout:
    print("timeout")
except OSError as e:
    print(errno.errorcode.get(e.errno, str(e.errno)))
`

type verdict struct {
	rule              string
	deny, mode, isDef uint32
}

// Hook values of the verdict event (enum net_hook in program.bpf.c).
var tierHooks = map[string][]uint32{TierLSM: {0, 1}, TierCgroup: {2, 3, 4, 5}}

type kernelFixture struct {
	ctx       context.Context
	id, other string
	container ContainerIdentity
	compiled  netpolicy.Compiled
	bindings  *enforcement.Bindings
	mu        sync.Mutex
	verdicts  []verdict
	hooks     map[uint32]int
}

func identity(t *testing.T, runtime, id, cgroupPath string) ContainerIdentity {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", cgroupPath), &st); err != nil {
		t.Fatal(err)
	}
	return ContainerIdentity{Runtime: runtime, ID: id, CgroupID: st.Ino, CgroupPath: cgroupPath}
}

func newKernelFixture(t *testing.T) *kernelFixture {
	t.Helper()
	if os.Getenv("NETWORK_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	id := os.Getenv("NETWORK_CONTAINER_ID")
	return &kernelFixture{ctx: ctx, id: id, other: os.Getenv("NETWORK_OTHER_CONTAINER_ID"),
		container: identity(t, "docker", id, os.Getenv("NETWORK_CGROUP_PATH"))}
}

// start runs the gadget with a program tier. It returns the StartGadget error
// instead of failing, so a caller can tell an unsupported tier apart.
func (f *kernelFixture) start(t *testing.T, compiled netpolicy.Compiled, tier string) error {
	t.Helper()
	f.compiled = compiled
	f.hooks = map[uint32]int{}
	store, err := orasoci.NewFromTar(f.ctx, os.Getenv("NETWORK_IMAGE_ARCHIVE"))
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
	events := simple.New("network-test-verdicts", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		var err error
		if f.bindings, err = GetBindings(gc); err != nil {
			return err
		}
		ds := gc.GetDataSources()["verdict"]
		ruleID, deny, mode, isDef := ds.GetField("rule_id"), ds.GetField("deny"), ds.GetField("mode"), ds.GetField("is_default")
		hook := ds.GetField("hook_raw")
		return ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
			var v verdict
			h, _ := hook.Uint32(data)
			r, _ := ruleID.Uint32(data)
			v.deny, _ = deny.Uint32(data)
			v.mode, _ = mode.Uint32(data)
			v.isDef, _ = isDef.Uint32(data)
			if int(r) < len(f.compiled.RuleNames) {
				v.rule = f.compiled.RuleNames[r]
			}
			f.mu.Lock()
			f.verdicts = append(f.verdicts, v)
			f.hooks[h]++
			f.mu.Unlock()
			return nil
		}, 100)
	}))
	desired := &api.GadgetInstance{Id: "network-kernel-test", GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol,
		ImageName: os.Getenv("NETWORK_IMAGE"), ParamValues: map[string]string{TierParam: tier}}}
	if err := manager.StartGadget(f.ctx, desired, gadgetcontext.WithOrasReadonlyTarget(store),
		gadgetcontext.WithAdditionalDataOperators(handler, New(), events),
		WithConfig(Config{Policy: compiled})); err != nil {
		return err
	}
	t.Cleanup(func() { manager.StopGadget(context.Background(), desired.Id) })
	return nil
}

// checkHooks fails when a verdict came from a program of the other tier.
func (f *kernelFixture) checkHooks(t *testing.T, tier string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	t.Logf("verdicts per hook: %v", f.hooks)
	for h := range f.hooks {
		if !slices.Contains(tierHooks[tier], h) {
			t.Errorf("verdict from hook %d with tier %s", h, tier)
		}
	}
}

// call runs the probe in a container and returns its result line.
func (f *kernelFixture) call(t *testing.T, container, kind, host string, port int) string {
	t.Helper()
	out, err := exec.CommandContext(f.ctx, "docker", "exec", container, "python3", "-c", probe, kind, host, fmt.Sprint(port)).CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %s: %v: %s", kind, err, out)
	}
	return strings.TrimSpace(string(out))
}

// expect runs the probe and compares its result line with want: EPERM for a
// deny, else the result of the kernel alone (OK, timeout, ECONNREFUSED, ...).
func (f *kernelFixture) expect(t *testing.T, container, kind, host string, port int, want string) {
	t.Helper()
	got := f.call(t, container, kind, host, port)
	t.Logf("%s %s:%d in %.12s = %s", kind, host, port, container, got)
	if got != want {
		t.Errorf("%s %s:%d in %.12s = %s, want %s", kind, host, port, container, got, want)
	}
}

// waitVerdict waits for a verdict event that matches want.
func (f *kernelFixture) waitVerdict(t *testing.T, want verdict) {
	t.Helper()
	for i := 0; i < 20; i++ {
		f.mu.Lock()
		for _, v := range f.verdicts {
			if v == want {
				f.mu.Unlock()
				return
			}
		}
		f.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("no verdict event %+v", want)
}

// defaultDeny allows only loopback.
var defaultDeny = netpolicy.Document{Version: 1, Name: "deny-all", Policy: netpolicy.Policy{Mode: "enforce", Egress: netpolicy.Section{
	Default: "deny", Rules: []netpolicy.Rule{{Name: "loopback", Action: "allow", CIDRs: []string{"127.0.0.0/8", "::1/128"}}}}}}

func TestGadgetWithInspektorGadgetAlone(t *testing.T) {
	f := newKernelFixture(t)
	compiled := matrixPolicy(t)
	if err := f.start(t, compiled, TierLSM); err != nil {
		t.Fatal(err)
	}
	f.matrix(t, TierLSM)
}

func TestGadgetCgroupTier(t *testing.T) {
	f := newKernelFixture(t)
	compiled := matrixPolicy(t)
	if err := f.start(t, compiled, TierCgroup); err != nil {
		if strings.Contains(err.Error(), "unsupported program") {
			t.Skipf("the linked Inspektor Gadget cannot attach cgroup programs: %v", err)
		}
		t.Fatal(err)
	}
	f.matrix(t, TierCgroup)
}

// matrixPolicy compiles slot 0: the example policy; slot 1: default deny.
func matrixPolicy(t *testing.T) netpolicy.Compiled {
	t.Helper()
	file, err := os.Open("../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	example, err := netpolicy.Parse(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := netpolicy.CompileSlots([][]netpolicy.Document{{example}, {defaultDeny}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// checkLoaded fails when a program of the selected tier is not loaded. With
// NETWORK_UNUSED_TIER_UNLOADED=1 (an Inspektor Gadget that does not load
// disabled programs) it also fails when a program of the other tier is loaded.
// It reads every program on the node by name, so run one instance at a time.
func checkLoaded(t *testing.T, tier string) {
	t.Helper()
	loaded := map[string]bool{}
	for id := ebpf.ProgramID(0); ; {
		next, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			break
		}
		id = next
		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		if info, err := prog.Info(); err == nil {
			loaded[info.Name] = true
		}
		prog.Close()
	}
	for name, programs := range tierPrograms {
		for _, p := range programs {
			t.Logf("program %s (tier %s) loaded: %v", p, name, loaded[p])
			switch {
			case name == tier && !loaded[p]:
				t.Errorf("program %s of the selected tier is not loaded", p)
			case name != tier && loaded[p] && os.Getenv("NETWORK_UNUSED_TIER_UNLOADED") == "1":
				t.Errorf("program %s of the unused tier is loaded", p)
			}
		}
	}
}

// matrix is the case matrix of both tiers.
func (f *kernelFixture) matrix(t *testing.T, tier string) {
	checkLoaded(t, tier)
	defer f.checkHooks(t, tier)
	f.expect(t, f.id, "tcp4", "192.0.2.1", 80, "timeout")
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 0}); err != nil {
		t.Fatal(err)
	}
	// Denied for the bound container. The unselected container gets the
	// result of the kernel alone (allowed): the test networks have no
	// route over IPv6 and do not answer over IPv4.
	denied := []struct {
		kind, host string
		port       int
		allowed    string
	}{
		{"tcp4", "192.0.2.1", 80, "timeout"},
		{"tcp4-fastopen", "192.0.2.1", 80, "EINPROGRESS"},
		{"tcp6", "2001:db8::1", 80, "ENETUNREACH"},
		{"tcp6", "::ffff:192.0.2.1", 80, "timeout"},
		{"udp-connect", "192.0.2.1", 53, "OK"},
		{"udp4-sendto", "192.0.2.1", 53, "OK"},
		{"udp6-sendto", "2001:db8::1", 53, "ENETUNREACH"},
		{"udp6-sendto", "::ffff:192.0.2.1", 53, "OK"},
		{"udp6-sendto-sockaddr_in", "192.0.2.1", 53, "OK"},
		{"udp4-sendto-unspec", "192.0.2.1", 53, "OK"},
		{"udp-connected-sendto", "192.0.2.1", 53, "OK"},
		{"udp4-sendto", "203.0.113.5", 53, "OK"},
		{"udp4-sendto", "203.0.113.5", 5350, "OK"},
	}
	t.Run("enforce", func(t *testing.T) {
		for _, c := range denied {
			f.expect(t, f.id, c.kind, c.host, c.port, "EPERM")
		}
		f.waitVerdict(t, verdict{rule: "example/no-test-net-1", deny: 1, mode: 2})
	})
	t.Run("raw", func(t *testing.T) {
		// rawv6_sendmsg reads an AF_UNSPEC address as AF_INET6. The
		// cgroup programs do not run for raw sockets.
		want := "ENETUNREACH"
		if tier == TierLSM {
			want = "EPERM"
		}
		f.expect(t, f.id, "raw6-sendto-unspec", "2001:db8::1", 0, want)
	})
	t.Run("sendmmsg partial", func(t *testing.T) {
		if got := f.call(t, f.id, "udp4-sendmmsg", "192.0.2.1", 53); got != "sent 1" {
			t.Errorf("sendmmsg [allowed, denied] = %s, want sent 1", got)
		}
		if got := f.call(t, f.other, "udp4-sendmmsg", "192.0.2.1", 53); got != "OK" {
			t.Errorf("sendmmsg in the unselected container = %s, want OK", got)
		}
	})
	t.Run("allowed", func(t *testing.T) {
		f.expect(t, f.id, "tcp4", "192.0.2.7", 80, "timeout")     // except
		f.expect(t, f.id, "udp4-sendto", "203.0.113.5", 54, "OK") // other port
		f.expect(t, f.id, "tcp4", "203.0.113.5", 53, "timeout")   // other protocol
		f.expect(t, f.id, "tcp4", "127.0.0.1", 9, "ECONNREFUSED")
		f.expect(t, f.id, "tcp4-connected-sendto", "192.0.2.1", 80, "OK")
	})
	t.Run("fastopen on a connected socket", func(t *testing.T) {
		// The LSM tier judges every MSG_FASTOPEN send, because the socket
		// state can change before tcp_sendmsg reads it: EPERM, where the
		// kernel alone returns EISCONN. The cgroup programs do not run for
		// a TCP send.
		want := "EISCONN"
		if tier == TierLSM {
			want = "EPERM"
		}
		for _, c := range []struct{ container, want string }{{f.id, want}, {f.other, "EISCONN"}} {
			got := f.call(t, c.container, "tcp4-connected-fastopen", "192.0.2.1", 80)
			t.Logf("tcp4-connected-fastopen 192.0.2.1:80 in %.12s = %s", c.container, got)
			if got != c.want {
				t.Errorf("tcp4-connected-fastopen in %.12s = %s, want %s", c.container, got, c.want)
			}
		}
	})
	t.Run("audit", func(t *testing.T) {
		f.expect(t, f.id, "tcp4", "198.51.100.1", 80, "timeout")
		f.waitVerdict(t, verdict{rule: "example/watch-test-net-2", deny: 1, mode: 1})
	})
	t.Run("unselected container", func(t *testing.T) {
		for _, c := range denied {
			f.expect(t, f.other, c.kind, c.host, c.port, c.allowed)
		}
	})
	t.Run("live move to default deny", func(t *testing.T) {
		if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 1}); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.CommandContext(f.ctx, "docker", "exec", f.id, "true").CombinedOutput(); err != nil {
			t.Fatalf("docker exec under default deny: %v: %s", err, out)
		}
		f.expect(t, f.id, "tcp4", "192.0.2.7", 80, "EPERM")
		f.expect(t, f.id, "tcp4", "127.0.0.1", 9, "ECONNREFUSED")
		f.waitVerdict(t, verdict{rule: "default", deny: 1, mode: 2, isDef: 1})
	})
	t.Run("unbind", func(t *testing.T) {
		if err := f.bindings.Unbind(f.container); err != nil {
			t.Fatal(err)
		}
		f.expect(t, f.id, "tcp4", "192.0.2.1", 80, "timeout")
	})
	t.Run("docker run under default deny", func(t *testing.T) {
		parent, image := os.Getenv("NETWORK_PARENT_CGROUP"), os.Getenv("NETWORK_RUN_IMAGE")
		if parent == "" || image == "" {
			t.Skip("NETWORK_PARENT_CGROUP and NETWORK_RUN_IMAGE not set")
		}
		holder := identity(t, "test", "parent-cgroup", parent)
		if err := f.bindings.Bind(enforcement.Binding{Container: holder, Slot: 1}); err != nil {
			t.Fatal(err)
		}
		defer f.bindings.Unbind(holder)
		run := func(host string, port int) string {
			out, err := exec.CommandContext(f.ctx, "docker", "run", "--rm", "--cgroup-parent="+os.Getenv("NETWORK_CGROUP_PARENT"),
				image, "python3", "-c", probe, "tcp4", host, fmt.Sprint(port)).CombinedOutput()
			if err != nil {
				t.Fatalf("docker run under default deny: %v: %s", err, out)
			}
			return strings.TrimSpace(string(out))
		}
		if got := run("192.0.2.7", 80); got != "EPERM" {
			t.Errorf("new container connect = %s, want EPERM", got)
		}
		if got := run("127.0.0.1", 9); got != "ECONNREFUSED" {
			t.Errorf("new container loopback connect = %s, want ECONNREFUSED", got)
		}
	})
}
