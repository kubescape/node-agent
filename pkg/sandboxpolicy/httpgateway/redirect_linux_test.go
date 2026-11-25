// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

// Kernel tests of the redirect. They need root, cgroup v2 at /sys/fs/cgroup
// and a bpffs at /sys/fs/bpf, and are skipped without them. They must run in
// the initial pid namespace (in a container: --pid host), because conns holds
// the pid as the kernel's initial namespace sees it. Each test makes
// its own cgroups, pin directory and loopback listeners, so nothing outside
// the test is redirected: only a task in a bound cgroup that connects to an
// address in that binding's set is touched.
//
// The clients are this test binary, started again inside a test cgroup
// (HTTPGW_TEST_CLIENT). Each connection sends the client's pid; the listener
// standing in for the gateway looks the connection up in `conns` by its remote
// address and compares.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	testCgroupRoot = "/sys/fs/cgroup"
	testBPFFS      = "/sys/fs/bpf"
	clientEnv      = "HTTPGW_TEST_CLIENT"
)

var (
	aiHost      = netip.MustParseAddr("127.0.0.2")
	otherHost   = netip.MustParseAddr("127.0.0.4")
	gatewayAddr = netip.MustParseAddrPort("127.0.0.3:18443")
)

// clientResult is what one client process reports.
type clientResult struct {
	PID     int            `json:"pid"`
	Replies map[string]int `json:"replies"`
	Errors  []string       `json:"errors,omitempty"`
}

// TestMain runs the client when the binary was started as one.
func TestMain(m *testing.M) {
	if spec := os.Getenv(clientEnv); spec != "" {
		runClient(spec)
		return
	}
	os.Exit(m.Run())
}

// runClient makes count connections to target, one at a time. spec is
// "<network>,<target>,<count>": network tcp4, mapped (an AF_INET6 socket to
// the IPv4-mapped form), udp4, tcp6, or hold4 (tcp4; print the reply, then
// keep the connection until the other side or the kernel ends it).
func runClient(spec string) {
	parts := strings.Split(spec, ",")
	count, _ := strconv.Atoi(parts[2])
	target := netip.MustParseAddrPort(parts[1])
	out := clientResult{PID: os.Getpid(), Replies: map[string]int{}}
	fail := func(err error) {
		if len(out.Errors) < 5 {
			out.Errors = append(out.Errors, err.Error())
		}
		out.Replies["error"]++
	}
	for i := 0; i < count; i++ {
		reply, err := dialOnce(parts[0], target, out.PID)
		if err != nil {
			fail(err)
			continue
		}
		out.Replies[reply]++
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func dialOnce(network string, target netip.AddrPort, pid int) (string, error) {
	family, typ := unix.AF_INET, unix.SOCK_STREAM
	var sa unix.Sockaddr
	switch network {
	case "mapped":
		family = unix.AF_INET6
		sa = &unix.SockaddrInet6{Port: int(target.Port()), Addr: v4Mapped(target.Addr())}
	case "tcp6", "hold6":
		family = unix.AF_INET6
		sa = &unix.SockaddrInet6{Port: int(target.Port()), Addr: target.Addr().As16()}
	case "udp4":
		typ = unix.SOCK_DGRAM
		fallthrough
	default:
		sa = &unix.SockaddrInet4{Port: int(target.Port()), Addr: target.Addr().As4()}
	}
	fd, err := unix.Socket(family, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	if network == "udp4" {
		if err := unix.Sendto(fd, []byte("x"), 0, sa); err != nil {
			return "", fmt.Errorf("sendto: %w", err)
		}
		return "sent", nil
	}
	tv := unix.Timeval{Sec: 5}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	if err := unix.Connect(fd, sa); err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	if _, err := unix.Write(fd, []byte(strconv.Itoa(pid)+"\n")); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 64)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	reply := strings.TrimSpace(string(buf[:n]))
	if network != "hold4" && network != "hold6" {
		return reply, nil
	}
	// Say where the connection went, then wait for its end.
	fmt.Println(reply)
	tv = unix.Timeval{Sec: 30}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_, err = unix.Read(fd, buf)
	switch {
	case err == nil:
		return "ended: closed", nil
	case errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR):
		// The receive timeout, not something done to the socket.
		return "ended: timeout: " + err.Error(), nil
	case errors.Is(err, unix.ECONNABORTED) || errors.Is(err, unix.ECONNRESET):
		// bpf_sock_destroy aborts the socket.
		return resetReply, nil
	default:
		return "ended: " + err.Error(), nil
	}
}

// resetReply is what a held connection reports when the kernel reset it.
const resetReply = "ended: reset"

func v4Mapped(a netip.Addr) [16]byte {
	out := [16]byte{10: 0xff, 11: 0xff}
	v4 := a.As4()
	copy(out[12:], v4[:])
	return out
}

// env is one test's cgroups, listeners and loaded redirect.
type env struct {
	t        *testing.T
	pinDir   string
	cgroup   string // parent of the test's pod cgroups
	redirect *Redirect

	mu sync.Mutex
	// byPID is where the gateway listener saw each client pid: the cgroup and
	// original destination of the conns entry, or "miss".
	matched, missed, wrong int
	expect                 map[int]uint64 // client pid to the cgroup id its conns entries must carry
	lastOrigDst            netip.AddrPort
}

func newEnv(t *testing.T) *env {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	var st unix.Statfs_t
	if unix.Statfs(testCgroupRoot, &st) != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		t.Skip("needs cgroup v2 at " + testCgroupRoot)
	}
	if unix.Statfs(testBPFFS, &st) != nil || uint32(st.Type) != unix.BPF_FS_MAGIC {
		t.Skip("needs a bpffs at " + testBPFFS)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("httpgw-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	e := &env{t: t, pinDir: filepath.Join(testBPFFS, name), cgroup: filepath.Join(testCgroupRoot, name), expect: map[int]uint64{}}
	if err := os.Mkdir(e.cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e.redirect != nil {
			e.redirect.Close()
		}
		if err := Remove(e.pinDir); err != nil {
			t.Errorf("remove pins: %v", err)
		}
		removeCgroups(e.cgroup)
	})
	e.load()
	e.serve(netip.AddrPortFrom(aiHost, 443), "direct")
	e.serve(netip.AddrPortFrom(otherHost, 443), "direct-other")
	e.serveGateway()
	return e
}

func removeCgroups(dir string) {
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if entry.IsDir() {
			removeCgroups(filepath.Join(dir, entry.Name()))
		}
	}
	_ = unix.Rmdir(dir)
}

func (e *env) load() {
	e.t.Helper()
	r, err := Load(Options{PinDir: e.pinDir, CgroupRoot: testCgroupRoot, Gateway: gatewayAddr})
	if err != nil {
		e.t.Fatalf("load: %v", err)
	}
	e.redirect = r
}

// mkcgroup creates a cgroup under the test's parent and returns its path and id.
func (e *env) mkcgroup(rel string) (string, uint64) {
	e.t.Helper()
	dir := filepath.Join(e.cgroup, rel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		e.t.Fatal(err)
	}
	return dir, st.Ino
}

// serve answers every connection to addr with reply.
func (e *env) serve(addr netip.AddrPort, reply string) {
	e.t.Helper()
	l, err := net.Listen("tcp4", addr.String())
	if err != nil {
		e.t.Fatalf("listen %s: %v", addr, err)
	}
	e.t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				_, _ = r.ReadString('\n')
				_, _ = c.Write([]byte(reply + "\n"))
				// Keep the connection for as long as the client does.
				_, _ = r.ReadString('\n')
			}()
		}
	}()
}

// serveGateway stands in for the gateway listener: it looks each connection up
// in conns by its remote address, as the processor does, and checks the entry
// against the pid the client sent.
func (e *env) serveGateway() {
	e.t.Helper()
	l, err := net.Listen("tcp4", gatewayAddr.String())
	if err != nil {
		e.t.Fatalf("listen %s: %v", gatewayAddr, err)
	}
	e.t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go e.gatewayConn(c)
		}
	}()
}

func (e *env) gatewayConn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	line, _ := r.ReadString('\n')
	pid, _ := strconv.Atoi(strings.TrimSpace(line))
	remote := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	e.check(pid, ConnKey{Addr: remote.Addr().Unmap(), Port: remote.Port()})
	_, _ = c.Write([]byte("gateway\n"))
	// Keep the connection for as long as the client does.
	_, _ = r.ReadString('\n')
}

// check compares the conns entry of a connection with the client that made it.
func (e *env) check(pid int, k ConnKey) {
	key := encodeConnKey(k)
	var value [ConnValueSize]byte
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.redirect == nil {
		// No loader is running (the restart test): nothing to read with.
		e.missed++
		return
	}
	err := e.redirect.coll.Maps[MapConns].Lookup(key, &value)
	conn, decodeErr := decodeConn(value[:])
	switch {
	case err != nil || decodeErr != nil:
		e.missed++
	case int(conn.PID) == pid && conn.CgroupID == e.expect[pid] && conn.CgroupID != 0:
		e.matched++
		e.lastOrigDst = conn.OrigDst
	default:
		e.wrong++
		e.t.Logf("wrong entry for pid %d: %+v, want cgroup %d", pid, conn, e.expect[pid])
	}
}

// client starts a client in the cgroup at dir. Its conns entries must carry
// cgroup id wantCgroup.
func (e *env) client(dir string, wantCgroup uint64, network string, target netip.AddrPort, count int) (wait func() clientResult) {
	e.t.Helper()
	cg, err := os.Open(dir)
	if err != nil {
		e.t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	// The client makes blocking socket calls directly; without the runtime's
	// preemption signal they are never interrupted.
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s,%s,%d", clientEnv, network, target, count), "GODEBUG=asyncpreemptoff=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		e.t.Fatal(err)
	}
	// The pid is known only after start, and the client connects at once: hold
	// the lock across start so the gateway listener sees the expectation.
	e.mu.Lock()
	err = cmd.Start()
	if err == nil {
		e.expect[cmd.Process.Pid] = wantCgroup
	}
	e.mu.Unlock()
	cg.Close()
	if err != nil {
		e.t.Fatalf("start client: %v", err)
	}
	return func() clientResult {
		var out clientResult
		decodeErr := json.NewDecoder(stdout).Decode(&out)
		if err := cmd.Wait(); err != nil {
			e.t.Errorf("client: %v", err)
		}
		if decodeErr != nil {
			e.t.Errorf("client output: %v", decodeErr)
		}
		return out
	}
}

func (e *env) counts() (matched, missed, wrong int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.matched, e.missed, e.wrong
}

// waitConnsEmpty waits for the close callbacks of the last connections.
func (e *env) waitConnsEmpty() {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conns, err := e.redirect.Conns()
		if err != nil {
			e.t.Fatal(err)
		}
		if len(conns) == 0 {
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("conns still holds %d entries after the run: %v", len(conns), conns)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestAttributionUnderPortReuse is the PoC's attribution test: two pods, eight
// client processes each, 400 short connections per process, half of the
// processes on IPv4 sockets and half on dual-stack sockets. Every one of the
// 6,400 connections must reach the gateway with a conns entry that names the
// client's own pid and its bound cgroup, and conns must be empty afterwards.
// Pod a is bound by its container cgroup, pod b by the pod cgroup above it.
func TestAttributionUnderPortReuse(t *testing.T) {
	e := newEnv(t)
	const procs, perProc = 8, 400
	ctrA, idA := e.mkcgroup("pod-a/ctr")
	_, podB := e.mkcgroup("pod-b")
	ctrB, _ := e.mkcgroup("pod-b/ctr")
	for binding, cgroup := range map[uint32]uint64{1: idA, 2: podB} {
		if err := e.redirect.SetBinding(cgroup, Binding{ID: binding}); err != nil {
			t.Fatal(err)
		}
		if err := e.redirect.SetAIDst(binding, aiHost, 0); err != nil {
			t.Fatal(err)
		}
	}
	target := netip.AddrPortFrom(aiHost, 443)
	var waits []func() clientResult
	for i := 0; i < procs; i++ {
		network := "tcp4"
		if i%2 == 1 {
			network = "mapped"
		}
		waits = append(waits, e.client(ctrA, idA, network, target, perProc), e.client(ctrB, podB, network, target, perProc))
	}
	total := map[string]int{}
	for _, wait := range waits {
		res := wait()
		for reply, n := range res.Replies {
			total[reply] += n
		}
		if len(res.Errors) > 0 {
			t.Errorf("client %d: %v", res.PID, res.Errors)
		}
	}
	want := 2 * procs * perProc
	if total["gateway"] != want || len(total) != 1 {
		t.Errorf("replies %v, want %d from the gateway and nothing else", total, want)
	}
	matched, missed, wrong := e.counts()
	if matched != want || missed != 0 || wrong != 0 {
		t.Errorf("attribution: %d matched, %d missed, %d wrong; want %d matched", matched, missed, wrong, want)
	}
	e.mu.Lock()
	if e.lastOrigDst != target {
		t.Errorf("original destination %s, want %s", e.lastOrigDst, target)
	}
	e.mu.Unlock()
	e.waitConnsEmpty()
	stats, err := e.redirect.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Redirected != uint64(want) || stats.Established != uint64(want) || stats.Closed != uint64(want) {
		t.Errorf("stats %+v, want %d redirected, established and closed", stats, want)
	}
}

// TestOnlyBoundAIConnectionsAreTouched: an unbound cgroup, another address,
// another binding's address, an exempt address and a binding that is failing
// open all keep their own route; UDP to an AI address is refused and UDP to
// another address is not.
func TestOnlyBoundAIConnectionsAreTouched(t *testing.T) {
	e := newEnv(t)
	bound, boundID := e.mkcgroup("bound/ctr")
	unbound, _ := e.mkcgroup("unbound/ctr")
	if err := e.redirect.SetBinding(boundID, Binding{ID: 7}); err != nil {
		t.Fatal(err)
	}
	if err := e.redirect.SetAIDst(7, aiHost, 0); err != nil {
		t.Fatal(err)
	}
	// otherHost is an AI address of binding 8 only.
	if err := e.redirect.SetAIDst(8, otherHost, 0); err != nil {
		t.Fatal(err)
	}
	ai, other := netip.AddrPortFrom(aiHost, 443), netip.AddrPortFrom(otherHost, 443)
	one := func(dir string, network string, target netip.AddrPort) clientResult {
		t.Helper()
		return e.client(dir, boundID, network, target, 1)()
	}
	expect := func(name string, res clientResult, reply string) {
		t.Helper()
		if res.Replies[reply] != 1 {
			t.Errorf("%s: replies %v errors %v, want %q", name, res.Replies, res.Errors, reply)
		}
	}
	expect("bound pod to its AI address", one(bound, "tcp4", ai), "gateway")
	expect("unbound pod to the AI address", one(unbound, "tcp4", ai), "direct")
	expect("bound pod to another binding's address", one(bound, "tcp4", other), "direct-other")
	expect("bound pod, UDP to its AI address", one(bound, "udp4", ai), "error")
	expect("bound pod, UDP to another address", one(bound, "udp4", other), "sent")
	expect("unbound pod, UDP to the AI address", one(unbound, "udp4", ai), "sent")

	if err := e.redirect.SetAIDst(7, aiHost, 1); err != nil { // expired long ago
		t.Fatal(err)
	}
	expect("expired address", one(bound, "tcp4", ai), "direct")
	if err := e.redirect.SetAIDst(7, aiHost, 0); err != nil {
		t.Fatal(err)
	}

	if err := e.redirect.SetBinding(boundID, Binding{ID: 7, Gate: GateFailingOpen}); err != nil {
		t.Fatal(err)
	}
	expect("failing open, TCP", one(bound, "tcp4", ai), "direct")
	expect("failing open, UDP", one(bound, "udp4", ai), "sent")
	if err := e.redirect.SetBinding(boundID, Binding{ID: 7, Gate: GateRecovering}); err != nil {
		t.Fatal(err)
	}
	expect("recovering", one(bound, "tcp4", ai), "gateway")

	if err := e.redirect.AddExempt(netip.MustParsePrefix("127.0.0.2/32")); err != nil {
		t.Fatal(err)
	}
	expect("exempt address", one(bound, "tcp4", ai), "direct")
}

// TestRestartKeepsRedirecting: after Close the redirect still runs and conns
// keeps filling; the next Load adopts the links and the maps with their
// content.
func TestRestartKeepsRedirecting(t *testing.T) {
	e := newEnv(t)
	dir, id := e.mkcgroup("pod/ctr")
	if err := e.redirect.SetBinding(id, Binding{ID: 3, Posture: PostureDeny}); err != nil {
		t.Fatal(err)
	}
	if err := e.redirect.SetAIDst(3, aiHost, 0); err != nil {
		t.Fatal(err)
	}
	target := netip.AddrPortFrom(aiHost, 443)

	e.mu.Lock()
	e.redirect.Close()
	e.redirect = nil
	e.mu.Unlock()
	res := e.client(dir, id, "tcp4", target, 20)()
	if res.Replies["gateway"] != 20 {
		t.Fatalf("with no loader running: replies %v errors %v, want 20 from the gateway", res.Replies, res.Errors)
	}

	e.mu.Lock()
	e.load()
	e.mu.Unlock()
	if !e.redirect.Adopted {
		t.Error("second Load did not adopt the pinned links")
	}
	b, ok, err := e.redirect.Binding(id)
	if err != nil || !ok || b != (Binding{ID: 3, Posture: PostureDeny}) {
		t.Errorf("binding after restart: %+v %v %v", b, ok, err)
	}
	stats, err := e.redirect.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Established != 20 || stats.Closed != 20 {
		t.Errorf("stats after restart %+v, want the 20 connections made while no loader ran", stats)
	}
	res = e.client(dir, id, "tcp4", target, 20)()
	matched, missed, wrong := e.counts()
	if res.Replies["gateway"] != 20 || matched != 20 || wrong != 0 {
		t.Errorf("after restart: replies %v, %d matched %d missed %d wrong", res.Replies, matched, missed, wrong)
	}
}

// TestLSMSeesOriginalDestination checks the hook order the network section
// relies on: a BPF LSM socket_connect program runs before the redirect, sees
// the destination the pod asked for, and its deny stops the connection before
// anything is rewritten or recorded.
func TestLSMSeesOriginalDestination(t *testing.T) {
	lsms, _ := os.ReadFile("/sys/kernel/security/lsm")
	if !strings.Contains(","+strings.TrimSpace(string(lsms))+",", ",bpf,") {
		t.Skip("BPF LSM is not active on this kernel")
	}
	e := newEnv(t)
	dir, id := e.mkcgroup("pod/ctr")
	if err := e.redirect.SetBinding(id, Binding{ID: 5}); err != nil {
		t.Fatal(err)
	}
	if err := e.redirect.SetAIDst(5, aiHost, 0); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec("testdata/lsmprobe.bpfel.o")
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("%+v", verr)
		}
		t.Fatal(err)
	}
	defer coll.Close()
	if err := coll.Variables["watch_cgroup"].Set(id); err != nil {
		t.Fatal(err)
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["probe_connect"]})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	target := netip.AddrPortFrom(aiHost, 443)
	res := e.client(dir, id, "tcp4", target, 1)()
	if res.Replies["gateway"] != 1 {
		t.Fatalf("replies %v errors %v, want the gateway", res.Replies, res.Errors)
	}
	var seenAddr uint32
	var seenPort uint16
	if err := coll.Variables["seen_addr"].Get(&seenAddr); err != nil {
		t.Fatal(err)
	}
	if err := coll.Variables["seen_port"].Get(&seenPort); err != nil {
		t.Fatal(err)
	}
	// Both are in network order in memory.
	var rawAddr [4]byte
	var rawPort [2]byte
	binary.NativeEndian.PutUint32(rawAddr[:], seenAddr)
	binary.NativeEndian.PutUint16(rawPort[:], seenPort)
	if got := netip.AddrPortFrom(netip.AddrFrom4(rawAddr), binary.BigEndian.Uint16(rawPort[:])); got != target {
		t.Errorf("LSM saw %s, want the original destination %s", got, target)
	}

	before, err := e.redirect.Stats()
	if err != nil {
		t.Fatal(err)
	}
	a := aiHost.As4()
	if err := coll.Variables["deny_addr"].Set(binary.NativeEndian.Uint32(a[:])); err != nil {
		t.Fatal(err)
	}
	res = e.client(dir, id, "tcp4", target, 1)()
	if res.Replies["error"] != 1 || len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "operation not permitted") {
		t.Errorf("with the LSM deny: replies %v errors %v, want EPERM", res.Replies, res.Errors)
	}
	after, err := e.redirect.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if after.Redirected != before.Redirected {
		t.Errorf("the redirect ran for a connection the LSM denied: %d redirected before, %d after", before.Redirected, after.Redirected)
	}
}

// TestKillDirect: a connection opened before the bind is direct and stays so;
// the kill resets it, and leaves alone a connection to another address and a
// connection of the same pod that went through the gateway.
func TestKillDirect(t *testing.T) {
	e := newEnv(t)
	dir, id := e.mkcgroup("pod/ctr")
	ai, other := netip.AddrPortFrom(aiHost, 443), netip.AddrPortFrom(otherHost, 443)

	hold := func(target netip.AddrPort, wantReply string) func() string { return e.hold(dir, id, target, wantReply) }

	// Connections that came and went leave TIME_WAIT sockets behind, with the
	// same destination. They are not connections any more and are not counted.
	if res := e.client(dir, id, "tcp4", ai, 20)(); res.Replies["direct"] != 20 {
		t.Fatalf("before the bind: replies %v errors %v", res.Replies, res.Errors)
	}
	beforeBind := hold(ai, "direct")
	toOther := hold(other, "direct-other")
	if err := e.redirect.SetBinding(id, Binding{ID: 9}); err != nil {
		t.Fatal(err)
	}
	if err := e.redirect.SetAIDst(9, aiHost, 0); err != nil {
		t.Fatal(err)
	}
	afterBind := hold(ai, "gateway")
	if got := beforeBind(); got != "still open" {
		t.Fatalf("before the kill, the pre-bind connection: %s", got)
	}

	res, err := e.redirect.KillDirect(9)
	if errors.Is(err, ErrKillUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if res.Destroyed != 1 {
		t.Errorf("destroyed %d sockets of %d seen, want 1", res.Destroyed, res.Seen)
	}
	if got := beforeBind(); got != resetReply {
		t.Errorf("pre-bind connection after the kill: %q, want a reset", got)
	}
	if got := toOther(); got != "still open" {
		t.Errorf("connection to another address after the kill: %q", got)
	}
	if got := afterBind(); got != "still open" {
		t.Errorf("gateway connection after the kill: %q", got)
	}
}

// TestRealIPv6: real IPv6 to port 443 of an AI address is refused, so the
// client falls back to IPv4; IPv6 to any other address is left alone.
func TestRealIPv6(t *testing.T) {
	loopback6 := netip.MustParseAddrPort("[::1]:443")
	probe, err := net.Listen("tcp6", loopback6.String())
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	probe.Close()
	e := newEnv(t)
	l, err := net.Listen("tcp6", loopback6.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = bufio.NewReader(c).ReadString('\n')
			_, _ = c.Write([]byte("direct6\n"))
			c.Close()
		}
	}()
	dir, id := e.mkcgroup("pod/ctr")
	if err := e.redirect.SetBinding(id, Binding{ID: 4}); err != nil {
		t.Fatal(err)
	}
	res := e.client(dir, id, "tcp6", loopback6, 1)()
	if res.Replies["direct6"] != 1 {
		t.Errorf("IPv6 to an address outside the set: replies %v errors %v", res.Replies, res.Errors)
	}
	if err := e.redirect.SetAIDst(4, loopback6.Addr(), 0); err != nil {
		t.Fatal(err)
	}
	res = e.client(dir, id, "tcp6", loopback6, 1)()
	if res.Replies["error"] != 1 || len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "operation not permitted") {
		t.Errorf("IPv6 to an AI address: replies %v errors %v, want EPERM", res.Replies, res.Errors)
	}
	stats, err := e.redirect.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.IPv6Refused != 1 {
		t.Errorf("stats %+v, want 1 IPv6 refusal", stats)
	}
}

var _ Maps = (*Redirect)(nil)

// TestReconcilerOnKernelMaps runs the reconciler against the real maps: the
// entries it writes are the ones the programs read, the listings decode what
// was written, and ReplaceExempt leaves exactly the wanted ranges.
func TestReconcilerOnKernelMaps(t *testing.T) {
	e := newEnv(t)
	dir, id := e.mkcgroup("pod/ctr")
	_, podID := e.mkcgroup("pod")
	r := NewReconciler(e.redirect)
	r.StaticAI = []netip.Addr{aiHost}
	p := Pod{UID: "u", Namespace: "ns", Name: "pod", Prepared: "aa11", PodCgroup: podID, Containers: map[string]uint64{"ctr": id},
		Policies: []Policy{{Ref: PolicyRef{UID: "p", Generation: 1}, Deny: true}}}
	states, err := r.Apply([]Pod{p}, "aa11", Rotation{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	binding := states[0].BindingID
	bindings, err := e.redirect.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	want := Binding{ID: binding, Posture: PostureDeny}
	if len(bindings) != 2 || bindings[id] != want || bindings[podID] != want {
		t.Errorf("bindings %+v, want %+v for the pod and the container cgroup", bindings, want)
	}
	ai, err := e.redirect.AIDsts()
	if err != nil {
		t.Fatal(err)
	}
	if len(ai) != 1 || ai[AIDst{binding, aiHost}] != 0 {
		t.Errorf("ai_dsts %+v", ai)
	}
	res := e.client(dir, id, "tcp4", netip.AddrPortFrom(aiHost, 443), 1)()
	if res.Replies["gateway"] != 1 {
		t.Errorf("a pod the reconciler bound: replies %v errors %v, want the gateway", res.Replies, res.Errors)
	}
	if matched, missed, wrong := e.counts(); matched != 1 || missed != 0 || wrong != 0 {
		t.Errorf("attribution: %d matched, %d missed, %d wrong", matched, missed, wrong)
	}

	if _, err := r.Apply(nil, "aa11", Rotation{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	bindings, _ = e.redirect.Bindings()
	ai, _ = e.redirect.AIDsts()
	if len(bindings) != 0 || len(ai) != 0 {
		t.Errorf("after the pod went: bindings %+v ai_dsts %+v", bindings, ai)
	}

	first := []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12"), netip.MustParsePrefix("192.168.1.10/32"), netip.MustParsePrefix("fd00::/8")}
	second := []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12"), netip.MustParsePrefix("10.244.0.0/16")}
	for _, set := range [][]netip.Prefix{first, second} {
		if err := e.redirect.ReplaceExempt(set); err != nil {
			t.Fatal(err)
		}
		got, err := e.redirect.Exempt()
		if err != nil {
			t.Fatal(err)
		}
		have := map[netip.Prefix]bool{}
		for _, p := range got {
			have[p] = true
		}
		if len(got) != len(set) {
			t.Errorf("exempt %v, want %v", got, set)
		}
		for _, p := range set {
			if !have[p] {
				t.Errorf("exempt %v lacks %s", got, p)
			}
		}
	}
}

// hold starts a client that keeps one connection open; it returns once
// the client said where the connection went. ended reports "still open" or
// how the connection ended.
func (e *env) hold(dir string, id uint64, target netip.AddrPort, wantReply string) (ended func() string) {
	t := e.t
	t.Helper()
	cg, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cg.Close()
	cmd := exec.Command(os.Args[0])
	network := "hold4"
	if target.Addr().Is6() && !target.Addr().Is4In6() {
		network = "hold6"
	}
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s,%s,1", clientEnv, network, target), "GODEBUG=asyncpreemptoff=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	err = cmd.Start()
	if err == nil {
		e.expect[cmd.Process.Pid] = id
	}
	e.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	out := bufio.NewReader(stdout)
	line, err := out.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != wantReply {
		t.Fatalf("held connection to %s went to %q (%v), want %q", target, strings.TrimSpace(line), err, wantReply)
	}
	result := make(chan string, 1)
	go func() {
		var res clientResult
		if err := json.NewDecoder(out).Decode(&res); err != nil {
			result <- "no result: " + err.Error()
			return
		}
		for reply := range res.Replies {
			result <- reply
			return
		}
		result <- "no reply"
	}()
	last := ""
	return func() string {
		if last != "" {
			return last
		}
		select {
		case last = <-result:
			return last
		case <-time.After(500 * time.Millisecond):
			return "still open"
		}
	}
}

// gateEnv is a health gate over the real maps, with a clock the test moves and
// the kill running in the test's own network namespace.
type gateEnv struct {
	*env
	rec   *Reconciler
	gate  *HealthGate
	clock time.Time
	// duringKill is the node state Status would report while a kill runs,
	// read from the map: the gate value of the pod's bindings.
	duringKill []Gate
}

func (g *gateEnv) Kill(ctx context.Context, pod PodState) (KillResult, error) {
	bindings, err := g.redirect.Bindings()
	if err != nil {
		return KillResult{}, err
	}
	for _, b := range bindings {
		if b.ID == pod.BindingID {
			g.duringKill = append(g.duringKill, b.Gate)
			break
		}
	}
	return NetNSKiller{Redirect: g.redirect}.Kill(ctx, pod)
}

func newGateEnv(t *testing.T) *gateEnv {
	g := &gateEnv{env: newEnv(t), clock: time.Now()}
	g.rec = NewReconciler(g.redirect)
	g.rec.StaticAI = []netip.Addr{aiHost}
	g.gate = NewHealthGate(DefaultGateConfig(), g.redirect, g, g.rec.States, func() time.Time { return g.clock })
	g.gate.SetRowLock(g.rec.Rows)
	g.rec.InitialGate = g.gate.InitialGate
	return g
}

func (g *gateEnv) observe(d time.Duration, up bool) {
	g.t.Helper()
	g.clock = g.clock.Add(d)
	h := Health{Envoy: up, Processor: up, CertsAnswered: true, CanDecrypt: true, DecryptValidUntil: g.clock.Add(time.Hour), RootFingerprint: "aa11"}
	if err := g.gate.Observe(context.Background(), h); err != nil {
		g.t.Fatalf("observe: %v", err)
	}
}

// testPod makes a pod with one container cgroup and returns it with the
// container cgroup's path and id.
func (g *gateEnv) testPod(name string, deny bool) (Pod, string, uint64) {
	g.t.Helper()
	_, podID := g.mkcgroup(name)
	dir, id := g.mkcgroup(name + "/ctr")
	return Pod{UID: name, Namespace: "ns", Name: name, Prepared: "aa11", PodCgroup: podID, Containers: map[string]uint64{"ctr": id}, NetNS: "/proc/self/ns/net",
		Policies: []Policy{{Ref: PolicyRef{UID: "p-" + name, Generation: 1}, Deny: deny}}}, dir, id
}

// TestGatePerPodPosture: on one node, while the gateway is down, a pod with
// posture deny keeps redirecting and a pod with posture allow goes direct.
func TestGatePerPodPosture(t *testing.T) {
	g := newGateEnv(t)
	allow, allowDir, allowID := g.testPod("allow", false)
	deny, denyDir, denyID := g.testPod("deny", true)
	if _, err := g.rec.Apply([]Pod{allow, deny}, "aa11", Rotation{}, g.clock); err != nil {
		t.Fatal(err)
	}
	target := netip.AddrPortFrom(aiHost, 443)
	reply := func(dir string, id uint64) string {
		t.Helper()
		res := g.client(dir, id, "tcp4", target, 1)()
		for r := range res.Replies {
			return r
		}
		return fmt.Sprint(res.Errors)
	}
	g.observe(0, true)
	if a, d := reply(allowDir, allowID), reply(denyDir, denyID); a != "gateway" || d != "gateway" {
		t.Fatalf("healthy: allow pod went to %q, deny pod to %q", a, d)
	}
	g.observe(500*time.Millisecond, false)
	if a, d := reply(allowDir, allowID), reply(denyDir, denyID); a != "direct" || d != "gateway" {
		t.Errorf("gateway down: allow pod went to %q (want direct), deny pod to %q (want the gateway)", a, d)
	}
	// A pod bound while the gateway is down follows its posture at once.
	late, lateDir, lateID := g.testPod("late", false)
	if _, err := g.rec.Apply([]Pod{allow, deny, late}, "aa11", Rotation{}, g.clock); err != nil {
		t.Fatal(err)
	}
	if got := reply(lateDir, lateID); got != "direct" {
		t.Errorf("gateway down: a pod bound now went to %q, want direct", got)
	}
}

// TestGateRecoveryResetsWindowConnections: a connection opened while the gate
// failed open is direct. On recovery it is reset, and the reset happens while
// the pod's bindings still say recovering: before the gate reports the node
// as redirecting again. A flap shorter than the healthy time resets nothing.
func TestGateRecoveryResetsWindowConnections(t *testing.T) {
	g := newGateEnv(t)
	pod, dir, id := g.testPod("allow", false)
	states, err := g.rec.Apply([]Pod{pod}, "aa11", Rotation{}, g.clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.gate.Bound(context.Background(), states); errors.Is(err, ErrKillUnsupported) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	if st := g.gate.Status(); len(st.PreAttachBypass) != 0 {
		t.Skipf("the kill cannot run on this kernel: %+v", st.PreAttachBypass)
	}
	g.duringKill = nil
	target := netip.AddrPortFrom(aiHost, 443)
	g.observe(0, true)
	g.observe(500*time.Millisecond, false)
	inWindow := g.hold(dir, id, target, "direct")

	// A flap: healthy for nine seconds, down again.
	g.observe(500*time.Millisecond, true)
	g.observe(9*time.Second, true)
	g.observe(500*time.Millisecond, false)
	if got := inWindow(); got != "still open" || len(g.duringKill) != 0 {
		t.Fatalf("after a flap shorter than the healthy time: connection %q, kills %v", got, g.duringKill)
	}

	g.observe(500*time.Millisecond, true)
	g.observe(10*time.Second, true)
	if got := g.gate.Status().State; got != GateRedirecting {
		t.Fatalf("state %d after the recovery", got)
	}
	if !reflect.DeepEqual(g.duringKill, []Gate{GateRecovering}) {
		t.Errorf("gate values during the kill %v, want one kill at recovering", g.duringKill)
	}
	if got := inWindow(); got != resetReply {
		t.Errorf("the connection opened in the window: %q, want a reset", got)
	}
	res := g.client(dir, id, "tcp4", target, 1)()
	if res.Replies["gateway"] != 1 {
		t.Errorf("after the recovery: replies %v errors %v, want the gateway", res.Replies, res.Errors)
	}
}

// TestKillFollowsTheRedirectsTest: the kill leaves alone what the redirect
// would leave direct, an exempt destination and an expired entry, and resets
// the same connection once the address is live and not exempt.
func TestKillFollowsTheRedirectsTest(t *testing.T) {
	e := newEnv(t)
	dir, id := e.mkcgroup("pod/ctr")
	ai := netip.AddrPortFrom(aiHost, 443)
	held := e.hold(dir, id, ai, "direct")
	if err := e.redirect.SetBinding(id, Binding{ID: 9}); err != nil {
		t.Fatal(err)
	}
	kill := func() KillResult {
		t.Helper()
		res, err := e.redirect.KillDirect(9)
		if errors.Is(err, ErrKillUnsupported) {
			t.Skip(err)
		}
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if err := e.redirect.SetAIDst(9, aiHost, 1); err != nil { // expired long ago
		t.Fatal(err)
	}
	if res := kill(); res.Destroyed != 0 {
		t.Errorf("expired entry: destroyed %d", res.Destroyed)
	}
	if err := e.redirect.SetAIDst(9, aiHost, 0); err != nil {
		t.Fatal(err)
	}
	if err := e.redirect.AddExempt(netip.MustParsePrefix("127.0.0.0/24")); err != nil {
		t.Fatal(err)
	}
	if res := kill(); res.Destroyed != 0 {
		t.Errorf("exempt destination: destroyed %d", res.Destroyed)
	}
	if got := held(); got != "still open" {
		t.Fatalf("the connection after two kills that must not touch it: %q", got)
	}
	if err := e.redirect.ReplaceExempt(nil); err != nil {
		t.Fatal(err)
	}
	if res := kill(); res.Destroyed != 1 {
		t.Errorf("live, not exempt: destroyed %d, want 1", res.Destroyed)
	}
	if got := held(); got != resetReply {
		t.Errorf("the connection after the kill: %q, want a reset", got)
	}
}

// TestKillNativeIPv6: while the gate fails open, real IPv6 to an AI address is
// let through; the recovery's kill resets that connection too.
func TestKillNativeIPv6(t *testing.T) {
	loopback6 := netip.MustParseAddrPort("[::1]:443")
	probe, err := net.Listen("tcp6", loopback6.String())
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	probe.Close()
	e := newEnv(t)
	l, err := net.Listen("tcp6", loopback6.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				_, _ = r.ReadString('\n')
				_, _ = c.Write([]byte("direct6\n"))
				_, _ = r.ReadString('\n')
			}()
		}
	}()
	dir, id := e.mkcgroup("pod/ctr")
	if err := e.redirect.SetBinding(id, Binding{ID: 4, Gate: GateFailingOpen}); err != nil {
		t.Fatal(err)
	}
	if err := e.redirect.SetAIDst(4, loopback6.Addr(), 0); err != nil {
		t.Fatal(err)
	}
	held := e.hold(dir, id, loopback6, "direct6")
	if err := e.redirect.SetBinding(id, Binding{ID: 4, Gate: GateRecovering}); err != nil {
		t.Fatal(err)
	}
	res, err := e.redirect.KillDirect(4)
	if errors.Is(err, ErrKillUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if res.Destroyed != 1 {
		t.Errorf("destroyed %d, want the IPv6 connection", res.Destroyed)
	}
	if got := held(); got != resetReply {
		t.Errorf("the IPv6 connection after the kill: %q, want a reset", got)
	}
}
