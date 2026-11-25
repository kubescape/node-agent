// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

// gateFixture is a gate over in-memory maps with a clock the test moves.
type gateFixture struct {
	t     *testing.T
	maps  *fakeMaps
	gate  *HealthGate
	clock time.Time
	pods  []PodState
	// kills are the pod UIDs the killer was called for; killErr is what it
	// returns; atKill is the gate state Status reported during each call.
	kills   []string
	killErr error
	atKill  []Gate
	onKill  func()
}

func (f *gateFixture) Kill(_ context.Context, pod PodState) (KillResult, error) {
	f.kills = append(f.kills, pod.Pod.UID)
	if f.onKill != nil {
		f.onKill()
	}
	// Status takes the gate's lock, which Observe holds: read the map instead.
	// It must still say the window is open while the kill runs.
	for _, b := range f.maps.bindings {
		if b.ID == pod.BindingID {
			f.atKill = append(f.atKill, b.Gate)
			break
		}
	}
	return KillResult{}, f.killErr
}

// newGateFixture has one allow pod (binding 1, cgroups 100 and 101) and one
// deny pod (binding 2, cgroup 200).
func newGateFixture(t *testing.T) *gateFixture {
	f := &gateFixture{t: t, maps: newFakeMaps(), clock: now}
	f.maps.bindings[100] = Binding{ID: 1}
	f.maps.bindings[101] = Binding{ID: 1}
	f.maps.bindings[200] = Binding{ID: 2, Posture: PostureDeny}
	f.pods = []PodState{
		{Pod: Pod{UID: "allow", Namespace: "ns", Name: "allow"}, Decision: Decision{Bound: true}, BindingID: 1},
		{Pod: Pod{UID: "deny", Namespace: "ns", Name: "deny"}, Decision: Decision{Bound: true, Posture: PostureDeny}, BindingID: 2},
	}
	f.gate = NewHealthGate(DefaultGateConfig(), f.maps, f, func() []PodState { return f.pods }, func() time.Time { return f.clock })
	return f
}

func (f *gateFixture) healthy() Health {
	return Health{Envoy: true, Processor: true, CertsAnswered: true, CanDecrypt: true, DecryptValidUntil: f.clock.Add(30 * time.Minute), RootFingerprint: rootA}
}

// step moves the clock and feeds one round.
func (f *gateFixture) step(d time.Duration, h Health) {
	f.t.Helper()
	f.clock = f.clock.Add(d)
	if err := f.gate.Observe(context.Background(), h); err != nil {
		f.t.Fatalf("observe: %v", err)
	}
}

func (f *gateFixture) gates() [3]Gate {
	return [3]Gate{f.maps.bindings[100].Gate, f.maps.bindings[101].Gate, f.maps.bindings[200].Gate}
}

func (f *gateFixture) want(what string, state Gate, gates [3]Gate) {
	f.t.Helper()
	if got := f.gate.Status().State; got != state {
		f.t.Errorf("%s: state %d, want %d", what, got, state)
	}
	if got := f.gates(); got != gates {
		f.t.Errorf("%s: gate values %v, want %v (allow, allow, deny)", what, got, gates)
	}
}

const tick = 500 * time.Millisecond

func TestGateOpensOnFirstFailureAndPerPosture(t *testing.T) {
	for name, fail := range map[string]func(*Health){
		"envoy":         func(h *Health) { h.Envoy = false },
		"processor":     func(h *Health) { h.Processor = false },
		"cannotDecrypt": func(h *Health) { h.CanDecrypt = false },
	} {
		f := newGateFixture(t)
		f.step(0, f.healthy())
		f.want(name+": healthy", GateRedirecting, [3]Gate{0, 0, 0})
		h := f.healthy()
		fail(&h)
		f.step(tick, h)
		// The allow pod goes direct; the deny pod keeps redirecting.
		f.want(name+": first failed round", GateFailingOpen, [3]Gate{1, 1, 0})
		if st := f.gate.Status(); !st.Unhealthy || st.NodeControllerDegraded {
			t.Errorf("%s: status %+v, want unhealthy and not degraded", name, st)
		}
		if len(f.kills) != 0 {
			t.Errorf("%s: kills %v while opening", name, f.kills)
		}
	}
}

// A certificate probe that stops answering opens nothing by itself; the gate
// opens when the last known expiry comes within the margin, and not before.
func TestGateCertificateSignal(t *testing.T) {
	f := newGateFixture(t)
	h := f.healthy() // valid for 30 more minutes
	f.step(0, h)
	silent := Health{Envoy: true, Processor: true}
	f.step(tick, silent)
	f.want("certs stopped answering", GateRedirecting, [3]Gate{0, 0, 0})
	st := f.gate.Status()
	if !st.NodeControllerDegraded || st.Unhealthy || st.RootFingerprint != rootA || !st.DecryptValidUntil.Equal(h.DecryptValidUntil) {
		t.Errorf("status %+v: want degraded, not unhealthy, the last answer kept", st)
	}
	// 24 minutes 59 seconds after the answer: 5 minutes 1 second left.
	f.step(24*time.Minute+59*time.Second-tick, silent)
	f.want("one second before the margin", GateRedirecting, [3]Gate{0, 0, 0})
	f.step(2*time.Second, silent)
	f.want("inside the margin", GateFailingOpen, [3]Gate{1, 1, 0})

	// The node controller comes back with renewed certificates.
	f.step(tick, f.healthy())
	f.want("renewed, not yet healthy for long enough", GateFailingOpen, [3]Gate{1, 1, 0})
	f.step(10*time.Second, f.healthy())
	f.want("recovered", GateRedirecting, [3]Gate{0, 0, 0})
	if f.gate.Status().NodeControllerDegraded {
		t.Error("still degraded after the node controller answered")
	}

	// Before any answer there is no certificate signal at all.
	fresh := newGateFixture(t)
	fresh.step(0, silent)
	fresh.want("no answer ever", GateRedirecting, [3]Gate{0, 0, 0})
	if !fresh.gate.Status().NodeControllerDegraded {
		t.Error("no answer ever: not reported as degraded")
	}
}

func TestGateRecoveryKillsBeforeTheStatusFlips(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	down := Health{CertsAnswered: true, CanDecrypt: true, DecryptValidUntil: f.clock.Add(30 * time.Minute), RootFingerprint: rootA}
	f.step(tick, down)
	f.want("down", GateFailingOpen, [3]Gate{1, 1, 0})

	f.step(tick, f.healthy()) // healthy from here
	f.step(9*time.Second+tick, f.healthy())
	f.want("healthy for 9.5 s", GateFailingOpen, [3]Gate{1, 1, 0})
	if len(f.kills) != 0 {
		t.Fatalf("kills %v before the healthy time passed", f.kills)
	}
	f.step(tick, f.healthy())
	f.want("healthy for 10 s", GateRedirecting, [3]Gate{0, 0, 0})
	// Only the pod that failed open is killed, once, and while its bindings
	// were recovering: redirecting again, not yet reported as restored.
	if !reflect.DeepEqual(f.kills, []string{"allow"}) || !reflect.DeepEqual(f.atKill, []Gate{GateRecovering}) {
		t.Errorf("kills %v with gate values %v, want the allow pod once at recovering", f.kills, f.atKill)
	}
	f.step(tick, f.healthy())
	if len(f.kills) != 1 {
		t.Errorf("kills %v: a healthy round after the recovery killed again", f.kills)
	}
}

func TestGateFlapShorterThanHealthyTimeResetsNothing(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	down := Health{}
	f.step(tick, down)
	for i := 0; i < 5; i++ {
		f.step(tick, f.healthy())
		f.step(9*time.Second, f.healthy())
		f.want("healthy for 9 s", GateFailingOpen, [3]Gate{1, 1, 0})
		f.step(tick, down)
		f.want("down again", GateFailingOpen, [3]Gate{1, 1, 0})
	}
	if len(f.kills) != 0 {
		t.Errorf("kills %v: a flapping gateway must not reset connections", f.kills)
	}
}

// A kill that fails keeps the node recovering; a failure then reopens the
// window, and the next recovery kills again.
func TestGateRecoveringCanFailAgain(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	f.step(tick, Health{})
	f.step(tick, f.healthy())
	f.killErr = errors.New("boom")
	f.clock = f.clock.Add(10 * time.Second)
	if err := f.gate.Observe(context.Background(), f.healthy()); err == nil {
		t.Fatal("a failed kill was not reported")
	}
	f.want("kill failed", GateRecovering, [3]Gate{2, 2, 0})
	f.step(tick, Health{})
	f.want("failed during recovery", GateFailingOpen, [3]Gate{1, 1, 0})
	f.killErr = nil
	f.step(tick, f.healthy())
	f.step(10*time.Second, f.healthy())
	f.want("recovered", GateRedirecting, [3]Gate{0, 0, 0})
	if !reflect.DeepEqual(f.kills, []string{"allow", "allow"}) {
		t.Errorf("kills %v, want the failed one and the one of the second recovery", f.kills)
	}
}

func TestGateCountsKillsThatCannotRun(t *testing.T) {
	for name, err := range map[string]error{"old kernel": ErrKillUnsupported, "host network": ErrKillSkipped} {
		f := newGateFixture(t)
		f.killErr = err
		f.step(0, f.healthy())
		f.step(tick, Health{})
		f.step(tick, f.healthy())
		f.step(10*time.Second, f.healthy())
		f.want(name, GateRedirecting, [3]Gate{0, 0, 0})
		if got := f.gate.Status().PreAttachBypass; !reflect.DeepEqual(got, map[string]int64{"allow": 1}) {
			t.Errorf("%s: bypass %v, want the allow pod counted once", name, got)
		}
	}
}

// A new process finds a window the last one left open: it stays open until
// the healthy time has passed, and the recovery still kills.
func TestGateAdoptsAnOpenWindow(t *testing.T) {
	f := newGateFixture(t)
	f.maps.bindings[100] = Binding{ID: 1, Gate: GateRecovering}
	f.maps.bindings[101] = Binding{ID: 1, Gate: GateFailingOpen}
	f.step(0, f.healthy())
	if got := f.gate.Status().State; got != GateFailingOpen {
		t.Fatalf("state %d after the first round, want the window still open", got)
	}
	if got := f.gate.InitialGate(PostureAllow); got != GateFailingOpen {
		t.Errorf("a binding created in the window gets gate %d", got)
	}
	if got := f.gate.InitialGate(PostureDeny); got != GateRedirecting {
		t.Errorf("a deny binding created in the window gets gate %d", got)
	}
	f.step(10*time.Second, f.healthy())
	f.want("recovered", GateRedirecting, [3]Gate{0, 0, 0})
	if !reflect.DeepEqual(f.kills, []string{"allow"}) {
		t.Errorf("kills %v", f.kills)
	}
}

// Bound kills a pod bound just now, once; an adopted pod is left alone; a pod
// bound while the window is open is killed by the recovery instead.
func TestGateBound(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	fresh := PodState{Pod: Pod{UID: "fresh"}, Decision: Decision{Bound: true}, BindingID: 5, New: true}
	adopted := PodState{Pod: Pod{UID: "adopted"}, Decision: Decision{Bound: true}, BindingID: 6}
	if err := f.gate.Bound(context.Background(), []PodState{fresh, adopted}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.kills, []string{"fresh"}) {
		t.Errorf("kills %v, want the new pod only", f.kills)
	}

	f.step(tick, Health{})
	late := PodState{Pod: Pod{UID: "late"}, Decision: Decision{Bound: true}, BindingID: 7, New: true}
	f.maps.bindings[700] = Binding{ID: 7, Gate: f.gate.InitialGate(PostureAllow)}
	if err := f.gate.Bound(context.Background(), []PodState{late}); err != nil {
		t.Fatal(err)
	}
	if len(f.kills) != 1 {
		t.Errorf("kills %v: a pod bound in the window must wait for the recovery", f.kills)
	}
	f.pods = append(f.pods, late)
	f.step(tick, f.healthy())
	f.step(10*time.Second, f.healthy())
	if !reflect.DeepEqual(f.kills, []string{"fresh", "allow", "late"}) || f.maps.bindings[700].Gate != GateRedirecting {
		t.Errorf("kills %v, late pod's gate %d", f.kills, f.maps.bindings[700].Gate)
	}
}

func TestHTTPProber(t *testing.T) {
	validUntil := time.Date(2026, 11, 24, 13, 0, 0, 0, time.UTC)
	processorUp := true
	certs := `{"canDecrypt": true, "decryptValidUntil": "2026-11-24T13:00:00Z", "rootFingerprint": "AA11"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case HealthPathEnvoy:
		case HealthPathProcessor:
			if !processorUp {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		case HealthPathCerts:
			_, _ = w.Write([]byte(certs))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	p := HTTPProber{Base: srv.URL}
	want := Health{Envoy: true, Processor: true, CertsAnswered: true, CanDecrypt: true, DecryptValidUntil: validUntil, RootFingerprint: "aa11"}
	if got := p.Probe(context.Background()); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	processorUp, certs = false, "not json"
	if got := p.Probe(context.Background()); !reflect.DeepEqual(got, Health{Envoy: true}) {
		t.Errorf("processor down and a bad certs body: %+v", got)
	}
	srv.Close()
	if got := p.Probe(context.Background()); !reflect.DeepEqual(got, Health{}) {
		t.Errorf("listener gone: %+v", got)
	}
}

// Run probes at once, without waiting for the first interval.
func TestGateRunProbesAtOnce(t *testing.T) {
	f := newGateFixture(t)
	cfg := DefaultGateConfig()
	cfg.Interval = time.Hour
	f.gate = NewHealthGate(cfg, f.maps, f, func() []PodState { return f.pods }, nil)
	changed := make(chan struct{}, 4)
	f.gate.OnChange = func() { changed <- struct{}{} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.gate.Run(ctx, proberFunc(func(context.Context) Health { return Health{} }), nil)
		close(done)
	}()
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("no probe within 5 s of start")
	}
	cancel()
	<-done
	if got := f.gate.Status().State; got != GateFailingOpen {
		t.Errorf("state %d after a failed first probe", got)
	}
}

type proberFunc func(context.Context) Health

func (p proberFunc) Probe(ctx context.Context) Health { return p(ctx) }

// A recovery round and a reconcile that binds a new pod run at the same time.
// The gate reads the reconciler's pods and the reconciler asks the gate for
// the gate value of a new binding; neither may wait for the other.
func TestGateAndReconcilerDoNotDeadlock(t *testing.T) {
	maps := newFakeMaps()
	rec := NewReconciler(maps)
	kills := 0
	var killMu sync.Mutex
	killer := killerFunc(func(context.Context, PodState) (KillResult, error) {
		killMu.Lock()
		kills++
		killMu.Unlock()
		return KillResult{}, nil
	})
	clock := now
	var clockMu sync.Mutex
	gate := NewHealthGate(DefaultGateConfig(), maps, killer, rec.States, func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = clock.Add(6 * time.Second)
		return clock
	})
	rec.InitialGate = gate.InitialGate
	gate.SetRowLock(rec.Rows)
	healthy := func() Health {
		return Health{Envoy: true, Processor: true, CertsAnswered: true, CanDecrypt: true, DecryptValidUntil: now.Add(1000 * time.Hour), RootFingerprint: rootA}
	}
	ctx := context.Background()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			h := healthy()
			if i%7 == 0 {
				h = Health{} // down: the next healthy rounds recover
			}
			_ = gate.Observe(ctx, h)
		}
	}()
	go func() {
		defer wg.Done()
		var pods []Pod
		for i := 0; i < 400; i++ {
			pods = append(pods, pod(fmt.Sprintf("p%d", i), rootA, uint64(1000+10*i), policy("p", 1)))
			states, _ := rec.Apply(pods, rootA, Rotation{}, now)
			_ = gate.Bound(ctx, states)
		}
	}()
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the gate and the reconciler are waiting on each other")
	}
}

type killerFunc func(context.Context, PodState) (KillResult, error)

func (k killerFunc) Kill(ctx context.Context, pod PodState) (KillResult, error) { return k(ctx, pod) }

// A gate write that fails is tried again on the next round, in each state.
func TestGateRetriesFailedWrites(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	f.maps.failBinding = map[uint64]bool{101: true}
	f.clock = f.clock.Add(tick)
	if err := f.gate.Observe(context.Background(), Health{}); !errors.Is(err, errInjected) {
		t.Fatalf("error %v, want the write failure", err)
	}
	f.want("one write failed", GateFailingOpen, [3]Gate{1, 0, 0})
	f.maps.failBinding = nil
	f.step(tick, Health{})
	f.want("retried on the next unhealthy round", GateFailingOpen, [3]Gate{1, 1, 0})

	// Recovery: one binding does not reach recovering, so no kill runs.
	f.step(tick, f.healthy())
	f.maps.failBinding = map[uint64]bool{101: true}
	f.clock = f.clock.Add(10 * time.Second)
	if err := f.gate.Observe(context.Background(), f.healthy()); !errors.Is(err, errInjected) {
		t.Fatalf("error %v", err)
	}
	f.want("recovering write failed", GateRecovering, [3]Gate{2, 1, 0})
	if len(f.kills) != 0 {
		t.Errorf("kills %v while a binding still fails open", f.kills)
	}
	f.maps.failBinding = nil
	f.step(tick, f.healthy())
	f.want("recovered after the retry", GateRedirecting, [3]Gate{0, 0, 0})
	if !reflect.DeepEqual(f.atKill, []Gate{GateRecovering}) {
		t.Errorf("gate values at kill %v, want recovering", f.atKill)
	}

	// The last step: only the write back to redirecting fails. The kill has
	// run by then; the node stays recovering, and the next round finishes it
	// without killing again.
	f.step(tick, Health{})
	f.step(tick, f.healthy())
	f.maps.failWhen = func(cgroup uint64, b Binding) bool { return cgroup == 100 && b.Gate == GateRedirecting }
	f.clock = f.clock.Add(10 * time.Second)
	if err := f.gate.Observe(context.Background(), f.healthy()); !errors.Is(err, errInjected) {
		t.Fatalf("error %v, want the failed final write", err)
	}
	if got := f.gate.Status().State; got != GateRecovering {
		t.Errorf("state %d after a failed final write, want recovering", got)
	}
	if len(f.kills) != 2 {
		t.Fatalf("kills %v, want the second window's kill before the failed write", f.kills)
	}
	f.maps.failWhen = nil
	f.step(tick, f.healthy())
	f.want("final write retried", GateRedirecting, [3]Gate{0, 0, 0})
	if len(f.kills) != 2 {
		t.Errorf("kills %v, want no kill on the retry of the final write", f.kills)
	}
}

// A new allow binding created while the node recovers gets the recovering
// value, and is killed before the window ends.
func TestGateBindingCreatedDuringRecovery(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	f.step(tick, Health{})
	f.step(tick, f.healthy())
	f.killErr = errors.New("busy") // hold the node at recovering
	f.clock = f.clock.Add(10 * time.Second)
	_ = f.gate.Observe(context.Background(), f.healthy())
	if got := f.gate.Status().State; got != GateRecovering {
		t.Fatalf("state %d", got)
	}
	if got := f.gate.InitialGate(PostureAllow); got != GateRecovering {
		t.Errorf("a binding created while recovering gets %d, want recovering", got)
	}
	late := PodState{Pod: Pod{UID: "late"}, Decision: Decision{Bound: true}, BindingID: 7, New: true}
	f.maps.bindings[700] = Binding{ID: 7, Gate: f.gate.InitialGate(PostureAllow)}
	if err := f.gate.Bound(context.Background(), []PodState{late}); err != nil {
		t.Fatal(err)
	}
	f.pods = append(f.pods, late)
	f.killErr = nil
	f.kills = nil
	f.step(tick, f.healthy())
	if got := f.gate.Status().State; got != GateRedirecting {
		t.Fatalf("state %d", got)
	}
	if !reflect.DeepEqual(f.kills, []string{"allow", "late"}) || f.maps.bindings[700].Gate != GateRedirecting {
		t.Errorf("kills %v, late gate %d", f.kills, f.maps.bindings[700].Gate)
	}
}

// A pod that turns deny during a window still has its window connections
// closed on recovery.
func TestGateKillsAPodThatTurnedDeny(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	f.step(tick, Health{})
	// The reconciler rewrites the allow pod as deny: gate redirecting.
	f.maps.bindings[100] = Binding{ID: 1, Posture: PostureDeny}
	f.maps.bindings[101] = Binding{ID: 1, Posture: PostureDeny}
	f.pods[0].Decision.Posture = PostureDeny
	f.step(tick, f.healthy())
	f.step(10*time.Second, f.healthy())
	f.want("recovered", GateRedirecting, [3]Gate{0, 0, 0})
	if !reflect.DeepEqual(f.kills, []string{"allow"}) {
		t.Errorf("kills %v, want the pod that failed open, now deny", f.kills)
	}
}

// A bind-time kill that fails is tried again on each reconcile until it works.
func TestGateRetriesBindTimeKill(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	fresh := PodState{Pod: Pod{UID: "fresh"}, Decision: Decision{Bound: true}, BindingID: 5, New: true}
	f.killErr = errors.New("netns busy")
	if err := f.gate.Bound(context.Background(), []PodState{fresh}); err == nil {
		t.Fatal("the failed kill was not reported")
	}
	fresh.New = false // the next reconcile no longer calls it new
	if err := f.gate.Bound(context.Background(), []PodState{fresh}); err == nil {
		t.Fatal("the second failed kill was not reported")
	}
	f.killErr = nil
	if err := f.gate.Bound(context.Background(), []PodState{fresh}); err != nil {
		t.Fatal(err)
	}
	if err := f.gate.Bound(context.Background(), []PodState{fresh}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.kills, []string{"fresh", "fresh", "fresh"}) {
		t.Errorf("kills %v, want three tries and none after the success", f.kills)
	}
}

// A binding written with a gate value that was stale by then (the window
// closed in between) is set back to redirecting on the next Bound.
func TestGateBoundSweepsStaleGateValues(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	f.maps.bindings[700] = Binding{ID: 7, Gate: GateFailingOpen}
	if err := f.gate.Bound(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := f.maps.bindings[700].Gate; got != GateRedirecting {
		t.Errorf("gate %d, want redirecting", got)
	}
}

// A row written after its pod's kill (a container that started during
// recovery) sends the gate back for another kill before it publishes
// redirecting.
func TestGateRowAddedAfterKill(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	f.step(tick, Health{})
	f.step(tick, f.healthy())
	first := true
	f.onKill = func() {
		if first {
			first = false
			// The reconciler binds a new container cgroup of the pod while
			// its kill runs, with the value InitialGate gives now.
			f.maps.bindings[103] = Binding{ID: 1, Gate: f.gate.InitialGate(PostureAllow)}
		}
	}
	f.step(10*time.Second, f.healthy())
	if got := f.gate.Status().State; got != GateRecovering {
		t.Fatalf("state %d: a row written after the kill must hold the window open", got)
	}
	f.step(tick, f.healthy())
	if got := f.gate.Status().State; got != GateRedirecting {
		t.Fatalf("state %d after the second kill", got)
	}
	if !reflect.DeepEqual(f.kills, []string{"allow", "allow"}) || f.maps.bindings[103].Gate != GateRedirecting {
		t.Errorf("kills %v, new row %+v", f.kills, f.maps.bindings[103])
	}
}

// A pod with no network namespace yet keeps the window open for one healthy
// period (its container may have started after the pod list was read), then
// counts as done, with no bypass counted.
func TestGatePodWithoutNamespace(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	f.step(tick, Health{})
	f.step(tick, f.healthy())
	f.killErr = ErrKillNotReady
	f.step(10*time.Second, f.healthy())
	f.step(5*time.Second, f.healthy())
	if got := f.gate.Status().State; got != GateRecovering {
		t.Fatalf("state %d: the namespace-less pod must hold the window", got)
	}
	f.killErr = nil
	f.step(tick, f.healthy())
	if got := f.gate.Status().State; got != GateRedirecting {
		t.Fatalf("state %d once the container is there", got)
	}
	if len(f.kills) != 3 || len(f.gate.Status().PreAttachBypass) != 0 {
		t.Errorf("kills %v bypass %v", f.kills, f.gate.Status().PreAttachBypass)
	}

	// Never gets a container: done after one healthy period, no bypass.
	g := newGateFixture(t)
	g.step(0, g.healthy())
	g.step(tick, Health{})
	g.step(tick, g.healthy())
	g.killErr = ErrKillNotReady
	g.step(10*time.Second, g.healthy())
	g.step(10*time.Second, g.healthy())
	if got := g.gate.Status().State; got != GateRedirecting || len(g.gate.Status().PreAttachBypass) != 0 {
		t.Errorf("state %d bypass %v", got, g.gate.Status().PreAttachBypass)
	}
}

// A sweep never overwrites a row the reconciler turned deny. The gate is
// paused inside its sweep, holding the row lock, after it read the rows; the
// reconciler then turns the pod deny. The reconciler must wait for the sweep,
// and the row must end deny and redirecting with no other Apply after.
func TestGateSweepKeepsDenyWrittenMeanwhile(t *testing.T) {
	f := newGateFixture(t)
	rec := NewReconciler(f.maps)
	f.gate.SetRowLock(rec.Rows)
	rec.InitialGate = f.gate.InitialGate
	allow := pod("x", rootA, 300, policy("p", 1))
	allow.Containers = map[string]uint64{"main": 301}
	if _, err := rec.Apply([]Pod{allow}, rootA, Rotation{}, now); err != nil {
		t.Fatal(err)
	}
	f.step(0, f.healthy())

	inSweep, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.maps.mu.Lock()
	f.maps.onBindings = func() {
		once.Do(func() {
			close(inSweep)
			<-release
		})
	}
	f.maps.mu.Unlock()
	swept := make(chan struct{})
	go func() {
		defer close(swept)
		f.clock = f.clock.Add(tick)
		_ = f.gate.Observe(context.Background(), Health{}) // fails allow rows open
	}()
	<-inSweep
	f.maps.mu.Lock()
	f.maps.onBindings = nil
	f.maps.mu.Unlock()

	deny := policy("p", 2)
	deny.Deny = true
	turned := pod("x", rootA, 300, deny)
	turned.Containers = map[string]uint64{"main": 301}
	applied := make(chan error, 1)
	go func() {
		_, err := rec.Apply([]Pod{turned}, rootA, Rotation{}, now)
		applied <- err
	}()
	select {
	case err := <-applied:
		t.Fatalf("the reconciler wrote while the gate's sweep held the rows (err %v)", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-swept
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	for _, c := range []uint64{300, 301} {
		if b := f.maps.bindings[c]; b.Posture != PostureDeny || b.Gate != GateRedirecting {
			t.Errorf("cgroup %d: %+v, want deny and redirecting while the gateway is down", c, b)
		}
	}
}

// The wait for a namespace counts healthy time only: an unhealthy round in
// between starts it again.
func TestGateNamespaceWaitRestartsAfterUnhealthy(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	f.step(tick, Health{})
	f.step(tick, f.healthy())
	f.killErr = ErrKillNotReady
	f.step(10*time.Second, f.healthy()) // the wait starts
	f.step(5*time.Second, Health{})     // down again
	f.step(tick, f.healthy())
	f.step(10*time.Second, f.healthy()) // recovering again: a new wait starts
	if got := f.gate.Status().State; got != GateRecovering {
		t.Fatalf("state %d: the old wait must not end the new one at once", got)
	}
	f.step(10*time.Second, f.healthy())
	if got := f.gate.Status().State; got != GateRedirecting {
		t.Errorf("state %d after a full healthy wait", got)
	}
}

// A row added while the gate waits for a pod's namespace is not covered when
// the wait ends: only the rows the binding had when the wait began are.
func TestGateNamespaceWaitDoesNotCoverNewRows(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	f.step(tick, Health{})
	f.step(tick, f.healthy())
	f.killErr = ErrKillNotReady
	f.step(10*time.Second, f.healthy()) // the wait starts with rows 100, 101
	f.maps.bindings[103] = Binding{ID: 1, Gate: f.gate.InitialGate(PostureAllow)}
	f.step(10*time.Second, f.healthy()) // the wait ends; 103 is not covered
	if got := f.gate.Status().State; got != GateRecovering {
		t.Fatalf("state %d: a row added during the wait must keep the window open", got)
	}
	f.killErr = nil // the container's namespace is known now
	f.step(tick, f.healthy())
	if got := f.gate.Status().State; got != GateRedirecting {
		t.Errorf("state %d after the kill", got)
	}
}

// Recovery kills by binding id: a pod reported not bound because a write
// failed still has live rows that failed open, and is killed.
func TestGateRecoveryKillsPodReportedUnbound(t *testing.T) {
	f := newGateFixture(t)
	f.step(0, f.healthy())
	f.step(tick, Health{})
	f.pods[0].Decision.Bound = false // its AI set write failed
	f.step(tick, f.healthy())
	f.step(10*time.Second, f.healthy())
	f.want("recovered", GateRedirecting, [3]Gate{0, 0, 0})
	if len(f.kills) != 1 || f.kills[0] != "allow" {
		t.Errorf("kills %v, want the pod with live rows", f.kills)
	}
}
