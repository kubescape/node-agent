// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// managerEnv runs a Manager over the test's cgroups and listeners. The inputs
// are fields the test changes; the manager reads them on each refresh.
type managerEnv struct {
	*env
	mu       sync.Mutex
	pods     []Pod
	podsErr  error
	up       bool
	staticAI []netip.Addr
	probes   atomic.Int64
	statuses atomic.Int64
	socket   string
	m        *Manager
}

func (e *managerEnv) Probe(context.Context) Health {
	e.probes.Add(1)
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.up {
		return Health{}
	}
	return Health{Envoy: true, Processor: true, CertsAnswered: true, CanDecrypt: true, DecryptValidUntil: time.Now().Add(time.Hour), RootFingerprint: "aa11"}
}

func (e *managerEnv) set(f func()) {
	e.mu.Lock()
	f()
	e.mu.Unlock()
	if e.m != nil {
		e.m.Kick()
	}
}

func newManagerEnv(t *testing.T) *managerEnv {
	e := &managerEnv{env: newEnv(t), up: true, staticAI: []netip.Addr{aiHost}}
	// The manager owns the redirect; the env keeps none of its own.
	e.mu.Lock()
	e.env.mu.Lock()
	e.redirect.Close()
	e.redirect = nil
	e.env.mu.Unlock()
	e.mu.Unlock()
	e.socket = filepath.Join(shortTempDir(t), "lookup.sock")
	// Before the environment's cleanup (cleanups run last first): a test
	// that fails while the manager runs must not leave its loops running.
	t.Cleanup(func() {
		if e.m != nil {
			e.stop()
		}
	})
	return e
}

func (e *managerEnv) start() {
	e.t.Helper()
	e.mu.Lock()
	static := e.staticAI
	e.mu.Unlock()
	gate := DefaultGateConfig()
	gate.Interval, gate.HealthyFor = 20*time.Millisecond, 200*time.Millisecond
	m, err := StartManager(context.Background(), ManagerOptions{
		PinDir: e.pinDir, CgroupRoot: testCgroupRoot, Gateway: gatewayAddr, Prober: e, Gate: gate,
		LookupSocket: e.socket, StaticAI: static, RefreshInterval: 50 * time.Millisecond,
		Pods: func(context.Context) ([]Pod, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.pods, e.podsErr
		},
		Exempt: func(context.Context) ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")}, nil
		},
		Rotation: func(context.Context) (Rotation, error) { return Rotation{CurrentRoot: "aa11"}, nil },
		Report:   func(err error) { e.t.Logf("manager: %v", err) },
		OnStatus: func() { e.statuses.Add(1) },
	})
	if err != nil {
		e.t.Fatalf("start manager: %v", err)
	}
	e.m = m
	// The env's gateway listener reads conns through the manager's redirect.
	e.env.mu.Lock()
	e.redirect = m.redirect
	e.env.mu.Unlock()
}

func (e *managerEnv) stop() {
	e.env.mu.Lock()
	e.redirect = nil
	e.env.mu.Unlock()
	e.m.Close()
	e.m = nil
}

func (e *managerEnv) eventually(what string, cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			e.t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *managerEnv) status(policy string) api.HTTPNodeStatus {
	st, _ := e.m.PolicyStatus(policy)
	return st
}

func (e *managerEnv) lookup(cgroup uint64) (int, Workload) {
	e.t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", e.socket)
	}}}
	resp, err := client.Get("http://lookup" + LookupPath + "?cgroup=" + uitoa(cgroup))
	if err != nil {
		return 0, Workload{}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var w Workload
	_ = json.Unmarshal(body, &w)
	return resp.StatusCode, w
}

func uitoa(v uint64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestManagerLifecycle runs the whole node-agent side against the kernel: a
// selected pod is bound once the gateway said which root it has, its
// connection reaches the gateway, the lookup socket and the status answer for
// it; the gateway going down and coming back moves the gate and the status;
// and a restart adopts everything without killing again.
func TestManagerLifecycle(t *testing.T) {
	e := newManagerEnv(t)
	_, podID := e.mkcgroup("pod")
	dir, id := e.mkcgroup("pod/ctr")
	bound := Pod{UID: "u1", Namespace: "ns", Name: "bound", Prepared: "aa11", PodCgroup: podID, Containers: map[string]uint64{"ctr": id}, NetNS: "/proc/self/ns/net",
		ControllerKind: "Deployment", ControllerName: "app", Policies: []Policy{{Ref: PolicyRef{UID: "p", Generation: 4}}}}
	unprepared := Pod{UID: "u2", Namespace: "ns", Name: "unprepared", PodCgroup: 1 << 40, Policies: []Policy{{Ref: PolicyRef{UID: "p", Generation: 4}}}}
	e.pods = []Pod{bound, unprepared}
	ai, other := netip.AddrPortFrom(aiHost, 443), netip.AddrPortFrom(otherHost, 443)

	e.start()
	e.eventually("the pod to be bound", func() bool { return e.status("p").BoundPods == 1 })
	if e.probes.Load() == 0 {
		t.Error("bound before any probe")
	}
	if st := e.status("p"); st.Gate != api.HTTPGateRedirecting || len(st.NeedRestart) != 1 || st.NeedRestart[0] != "ns/unprepared" || st.PreAttachBypass != 0 {
		t.Errorf("status %+v", st)
	}
	if res := e.client(dir, id, "tcp4", ai, 3)(); res.Replies["gateway"] != 3 {
		t.Fatalf("bound pod: replies %v errors %v", res.Replies, res.Errors)
	}
	if matched, _, wrong := e.counts(); matched != 3 || wrong != 0 {
		t.Errorf("attribution: %d matched, %d wrong", matched, wrong)
	}
	code, w := e.lookup(id)
	if code != http.StatusOK || w.Pod != "bound" || w.Container != "ctr" || w.Controller.Name != "app" || len(w.Policies) != 1 || w.Policies[0] != (PolicyRef{UID: "p", Generation: 4}) {
		t.Errorf("lookup: %d %+v", code, w)
	}
	binding := w.BindingID
	if exempt, err := e.m.redirect.Exempt(); err != nil || len(exempt) != 1 {
		t.Errorf("exempt %v %v", exempt, err)
	}
	if e.statuses.Load() == 0 {
		t.Error("OnStatus was never called")
	}

	// The gateway goes down: the allow pod goes direct, and the status says so.
	e.set(func() { e.up = false })
	e.eventually("the gate to open", func() bool { return e.status("p").Gate == api.HTTPGateFailingOpen })
	if res := e.client(dir, id, "tcp4", ai, 1)(); res.Replies["direct"] != 1 {
		t.Errorf("gateway down: replies %v errors %v", res.Replies, res.Errors)
	}
	// A failed pod listing keeps the bindings.
	e.set(func() { e.podsErr = errors.New("api server away") })
	time.Sleep(150 * time.Millisecond)
	if e.status("p").BoundPods != 1 {
		t.Error("a failed pod listing unbound the pod")
	}
	e.set(func() { e.podsErr = nil })
	inWindow := e.hold(dir, id, ai, "direct")
	e.set(func() { e.up = true })
	e.eventually("the gate to close", func() bool { return e.status("p").Gate == api.HTTPGateRedirecting })
	e.eventually("the window's connection to end", func() bool { return inWindow() != "still open" })
	if got := inWindow(); got != resetReply {
		t.Errorf("the window's connection: %q, want a reset", got)
	}

	// Restart. While nothing runs, connections still go to the gateway. A
	// connection made now to an address that only the next process adds to the
	// AI set is direct: if the next process ran the kill again for an adopted
	// pod, it would be reset.
	e.stop()
	if res := e.client(dir, id, "tcp4", ai, 2)(); res.Replies["gateway"] != 2 {
		t.Errorf("while node-agent is down: replies %v errors %v", res.Replies, res.Errors)
	}
	acrossRestart := e.hold(dir, id, other, "direct-other")
	e.set(func() { e.staticAI = []netip.Addr{aiHost, otherHost} })
	probesBefore := e.probes.Load()
	e.start()
	e.eventually("a probe right after start", func() bool { return e.probes.Load() > probesBefore })
	e.eventually("the new address to be redirected", func() bool {
		res := e.client(dir, id, "tcp4", other, 1)()
		return res.Replies["gateway"] == 1
	})
	states := e.m.States()
	if len(states) == 0 || !states[0].Decision.Bound || states[0].BindingID != binding || states[0].New {
		t.Fatalf("after the restart: %+v, want the pod bound with binding %d, not new", states, binding)
	}
	if got := acrossRestart(); got != "still open" {
		t.Errorf("the direct connection made across the restart: %q, want it left alone", got)
	}
	if code, w := e.lookup(id); code != http.StatusOK || w.BindingID != binding {
		t.Errorf("lookup after the restart: %d %+v", code, w)
	}

	// A second restart, with the gateway down when node-agent comes up. Its
	// root is not known then, and the pod stays bound.
	e.stop()
	e.set(func() { e.up = false })
	e.start()
	e.eventually("the gate to open after the restart", func() bool { return e.m.GateStatus().State == GateFailingOpen })
	time.Sleep(150 * time.Millisecond) // several reconciles with no root
	states = e.m.States()
	if len(states) == 0 || !states[0].Decision.Bound || states[0].BindingID != binding {
		t.Fatalf("gateway down at start: %+v, want the pod still bound with binding %d", states, binding)
	}
	if got := e.m.GateStatus().RootFingerprint; got != "" {
		t.Fatalf("root %q known with the gateway down", got)
	}
	e.set(func() { e.up = true })
	e.eventually("the gate to close", func() bool {
		st := e.m.GateStatus()
		return st.State == GateRedirecting && st.RootFingerprint == "aa11"
	})
	if res := e.client(dir, id, "tcp4", ai, 1)(); res.Replies["gateway"] != 1 {
		t.Errorf("after the gateway came back: replies %v errors %v", res.Replies, res.Errors)
	}

	// The pod goes away.
	e.set(func() { e.pods = nil })
	e.eventually("the pod to be unbound", func() bool { return e.status("p").Gate == api.HTTPGateNotBound })
	if code, _ := e.lookup(id); code != http.StatusNotFound {
		t.Errorf("lookup of an unbound cgroup: %d", code)
	}
	e.stop()
}
