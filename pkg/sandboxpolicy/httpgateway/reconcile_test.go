// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeMaps is the pinned maps in memory. It is safe for concurrent use.
type fakeMaps struct {
	mu       sync.Mutex
	bindings map[uint64]Binding
	ai       map[AIDst]uint64
	conns    map[ConnKey]Conn
	// order records the writes, to check that the AI set is written before
	// the binding that uses it.
	order []string
	// failBinding and failAI make the next writes to a cgroup or a binding's
	// set fail while they hold true.
	failBinding map[uint64]bool
	failAI      map[uint32]bool
	// failWhen fails a binding write it returns true for.
	failWhen func(cgroup uint64, b Binding) bool
}

func newFakeMaps() *fakeMaps {
	return &fakeMaps{bindings: map[uint64]Binding{}, ai: map[AIDst]uint64{}, conns: map[ConnKey]Conn{}}
}

var errInjected = errors.New("injected map write failure")

func (f *fakeMaps) Bindings() (map[uint64]Binding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[uint64]Binding{}
	for k, v := range f.bindings {
		out[k] = v
	}
	return out, nil
}
func (f *fakeMaps) SetBinding(cgroup uint64, b Binding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failBinding[cgroup] || (f.failWhen != nil && f.failWhen(cgroup, b)) {
		return errInjected
	}
	f.bindings[cgroup] = b
	f.order = append(f.order, "binding")
	return nil
}
func (f *fakeMaps) DeleteBinding(cgroup uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.bindings, cgroup)
	return nil
}
func (f *fakeMaps) AIDsts() (map[AIDst]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[AIDst]uint64{}
	for k, v := range f.ai {
		out[k] = v
	}
	return out, nil
}
func (f *fakeMaps) SetAIDst(binding uint32, addr netip.Addr, expiry uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAI[binding] {
		return errInjected
	}
	f.ai[AIDst{binding, addr}] = expiry
	f.order = append(f.order, "ai")
	return nil
}
func (f *fakeMaps) DeleteAIDst(binding uint32, addr netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ai, AIDst{binding, addr})
	return nil
}
func (f *fakeMaps) Conns() (map[ConnKey]Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[ConnKey]Conn{}
	for k, v := range f.conns {
		out[k] = v
	}
	return out, nil
}

const (
	rootA = "aa11"
	rootB = "bb22"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func policy(uid string, generation int64) Policy {
	return Policy{Ref: PolicyRef{UID: uid, Generation: generation}}
}

func pod(uid string, prepared string, podCgroup uint64, policies ...Policy) Pod {
	return Pod{UID: uid, Namespace: "ns", Name: "pod-" + uid, ControllerKind: "Deployment", ControllerName: "app",
		Prepared: prepared, Policies: policies, PodCgroup: podCgroup, Containers: map[string]uint64{"main": podCgroup + 1, "side": podCgroup + 2}}
}

func TestDecide(t *testing.T) {
	deny := policy("p-deny", 3)
	deny.Deny = true
	off := policy("p-off", 1)
	off.Off = true
	rotating := Rotation{CurrentRoot: rootA, NextRoot: rootB, WindowEnds: now.Add(time.Hour)}
	ended := Rotation{CurrentRoot: rootA, NextRoot: rootB, WindowEnds: now.Add(-time.Second)}
	emergency := Rotation{CurrentRoot: rootA, NextRoot: rootB, WindowEnds: now.Add(time.Hour), Emergency: true}
	for _, tc := range []struct {
		name     string
		pod      Pod
		nodeRoot string
		rotation Rotation
		want     Decision
	}{
		{"no policy selects the pod", pod("1", rootA, 10), rootA, Rotation{},
			Decision{Reason: ReasonNoPolicy}},
		{"only a mode off policy", pod("1", rootA, 10, off), rootA, Rotation{},
			Decision{Reason: ReasonNoPolicy}},
		{"bound", pod("1", rootA, 10, policy("p", 2)), rootA, Rotation{},
			Decision{Bound: true, Policies: []PolicyRef{{"p", 2}}}},
		{"fingerprints are compared without case or spaces", pod("1", " AA11 , bb22", 10, policy("p", 2)), "Aa11", Rotation{},
			Decision{Bound: true, Policies: []PolicyRef{{"p", 2}}}},
		{"deny wins across policies, off does not count", pod("1", rootA, 10, policy("p", 2), deny, off), rootA, Rotation{},
			Decision{Bound: true, Posture: PostureDeny, Policies: []PolicyRef{{"p", 2}, {"p-deny", 3}}}},
		{"no annotation", pod("1", "", 10, policy("p", 2)), rootA, Rotation{},
			Decision{Policies: []PolicyRef{{"p", 2}}, NeedRestart: true, Reason: ReasonNotPrepared}},
		{"the node's root is not known yet", pod("1", rootA, 10, policy("p", 2)), "", Rotation{},
			Decision{Policies: []PolicyRef{{"p", 2}}, Reason: ReasonRootUnknown}},
		{"the pod trusts another root", pod("1", rootB, 10, policy("p", 2)), rootA, Rotation{},
			Decision{Policies: []PolicyRef{{"p", 2}}, NeedRestart: true, Reason: ReasonNodeRootAbsent}},
		{"inside the rotation window the old root is enough", pod("1", rootA, 10, policy("p", 2)), rootA, rotating,
			Decision{Bound: true, Policies: []PolicyRef{{"p", 2}}}},
		{"after the window a pod without the next root is unbound", pod("1", rootA, 10, policy("p", 2)), rootA, ended,
			Decision{Policies: []PolicyRef{{"p", 2}}, NeedRestart: true, Reason: ReasonNextRootAbsent}},
		{"after the window a restarted pod is bound", pod("1", rootA+","+rootB, 10, policy("p", 2)), rootA, ended,
			Decision{Bound: true, Policies: []PolicyRef{{"p", 2}}}},
		{"an emergency does not wait for the window", pod("1", rootA, 10, policy("p", 2)), rootA, emergency,
			Decision{Policies: []PolicyRef{{"p", 2}}, NeedRestart: true, Reason: ReasonNextRootAbsent}},
		{"once the node moved to the new root", pod("1", rootA+","+rootB, 10, policy("p", 2)), rootB, ended,
			Decision{Bound: true, Policies: []PolicyRef{{"p", 2}}}},
	} {
		if got := Decide(tc.pod, tc.nodeRoot, tc.rotation, now); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.name, got, tc.want)
		}
	}
}

func TestParseRotation(t *testing.T) {
	got, err := ParseRotation([]byte(`{"currentRoot":"AA11","nextRoot":"bb22","windowEnds":"2026-12-01T00:00:00Z","emergency":true}`))
	want := Rotation{CurrentRoot: "aa11", NextRoot: "bb22", WindowEnds: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), Emergency: true}
	if err != nil || !got.WindowEnds.Equal(want.WindowEnds) || got.CurrentRoot != want.CurrentRoot || got.NextRoot != want.NextRoot || !got.Emergency {
		t.Errorf("got %+v %v, want %+v", got, err, want)
	}
	got, err = ParseRotation([]byte(`{"currentRoot":"aa11","nextRoot":null,"windowEnds":null,"emergency":false}`))
	if err != nil || got != (Rotation{CurrentRoot: "aa11"}) {
		t.Errorf("no rotation: got %+v %v", got, err)
	}
	if got.mustHaveNext(now) {
		t.Error("no rotation: pods must not need a next root")
	}
	if _, err := ParseRotation([]byte(`{"windowEnds":"tomorrow"}`)); err == nil {
		t.Error("a bad time: no error")
	}
}

func TestReconcilerBindsAndUnbinds(t *testing.T) {
	maps := newFakeMaps()
	r := NewReconciler(maps)
	ai := netip.MustParseAddr("203.0.113.9")
	r.StaticAI = []netip.Addr{ai}
	deny := policy("p-deny", 1)
	deny.Deny = true
	off := policy("p-off", 1)
	off.Off = true
	pods := []Pod{
		pod("a", rootA, 100, policy("p", 2)),
		pod("b", rootA, 200, policy("p", 2), deny),
		pod("unprepared", "", 300, policy("p", 2)),
		pod("off", rootA, 400, off),
		pod("unselected", rootA, 500),
	}
	states, err := r.Apply(pods, rootA, Rotation{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 3 {
		t.Fatalf("states for %d pods, want 3 (a, b and the unprepared one): %+v", len(states), states)
	}
	a, b, unprepared := states[0], states[1], states[2]
	if !a.Decision.Bound || !a.New || a.BindingID == 0 || !b.Decision.Bound || b.BindingID == a.BindingID {
		t.Errorf("a %+v, b %+v: want both bound, new, with different ids", a, b)
	}
	if unprepared.Decision.Bound || !unprepared.Decision.NeedRestart || unprepared.BindingID != 0 {
		t.Errorf("unprepared pod: %+v", unprepared)
	}
	want := map[uint64]Binding{
		100: {ID: a.BindingID}, 101: {ID: a.BindingID}, 102: {ID: a.BindingID},
		200: {ID: b.BindingID, Posture: PostureDeny}, 201: {ID: b.BindingID, Posture: PostureDeny}, 202: {ID: b.BindingID, Posture: PostureDeny},
	}
	if !reflect.DeepEqual(maps.bindings, want) {
		t.Errorf("bindings %+v, want %+v", maps.bindings, want)
	}
	if !reflect.DeepEqual(maps.ai, map[AIDst]uint64{{a.BindingID, ai}: 0, {b.BindingID, ai}: 0}) {
		t.Errorf("ai_dsts %+v", maps.ai)
	}
	if maps.order[0] != "ai" || maps.order[1] != "ai" {
		t.Errorf("writes %v: the AI sets must be written before the bindings", maps.order)
	}
	owner, ok := r.Owner(101)
	if !ok || owner.Pod != "pod-a" || owner.Container != "main" || owner.BindingID != a.BindingID || owner.Controller.Kind != "Deployment" || !reflect.DeepEqual(owner.Policies, []PolicyRef{{"p", 2}}) {
		t.Errorf("owner of the container cgroup: %+v %v", owner, ok)
	}
	if owner, ok := r.Owner(100); !ok || owner.Container != "" || owner.BindingID != a.BindingID {
		t.Errorf("owner of the pod cgroup: %+v %v", owner, ok)
	}
	if _, ok := r.Owner(300); ok {
		t.Error("an unbound cgroup has an owner")
	}

	// The gate owns the gate value: a second Apply keeps it for allow pods.
	for cgroup, binding := range maps.bindings {
		binding.Gate = GateFailingOpen
		maps.bindings[cgroup] = binding
	}
	maps.order = nil
	states, err = r.Apply(pods, rootA, Rotation{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if states[0].New || states[0].BindingID != a.BindingID {
		t.Errorf("second apply: %+v, want the same binding, not new", states[0])
	}
	if maps.bindings[100].Gate != GateFailingOpen {
		t.Errorf("allow pod: gate %d after a second apply, want it kept", maps.bindings[100].Gate)
	}
	if maps.bindings[200].Gate != GateRedirecting {
		t.Errorf("deny pod: gate %d, want redirecting whatever the entry held", maps.bindings[200].Gate)
	}

	// Pod a is deleted and pod b's policy turns off.
	maps.conns[ConnKey{Addr: netip.MustParseAddr("10.0.0.1"), Port: 1}] = Conn{BindingID: 41}
	pods = []Pod{pod("b", rootA, 200, off), pod("c", rootA, 600, policy("p", 2))}
	states, err = r.Apply(pods, rootA, Rotation{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || !states[0].New || states[0].BindingID <= b.BindingID {
		t.Fatalf("states %+v: want pod c alone, new, with an id never used", states)
	}
	c := states[0].BindingID
	if !reflect.DeepEqual(maps.bindings, map[uint64]Binding{600: {ID: c}, 601: {ID: c}, 602: {ID: c}}) {
		t.Errorf("bindings %+v", maps.bindings)
	}
	if !reflect.DeepEqual(maps.ai, map[AIDst]uint64{{c, ai}: 0}) {
		t.Errorf("ai_dsts %+v: the sets of the bindings that went must go too", maps.ai)
	}
}

// TestReconcilerAdopts: a new process finds the bindings of the last one. A
// pod whose cgroup is bound keeps its id and is not new (so it is not killed
// again), and a new binding gets an id that nothing in the kernel carries.
func TestReconcilerAdopts(t *testing.T) {
	maps := newFakeMaps()
	maps.bindings[100] = Binding{ID: 7, Gate: GateFailingOpen}
	maps.bindings[101] = Binding{ID: 7, Gate: GateFailingOpen}
	maps.bindings[900] = Binding{ID: 8} // a pod that is gone
	maps.ai[AIDst{12, netip.MustParseAddr("203.0.113.9")}] = 0
	maps.conns[ConnKey{Addr: netip.MustParseAddr("10.0.0.1"), Port: 1}] = Conn{BindingID: 30}
	r := NewReconciler(maps)
	r.InitialGate = func(Posture) Gate { return GateFailingOpen }
	deny := policy("p-deny", 1)
	deny.Deny = true
	states, err := r.Apply([]Pod{pod("a", rootA, 100, policy("p", 2)), pod("new", rootA, 200, policy("p", 2)), pod("new-deny", rootA, 300, deny)}, rootA, Rotation{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if states[0].BindingID != 7 || states[0].New {
		t.Errorf("adopted pod: %+v, want binding 7, not new", states[0])
	}
	if states[1].BindingID != 31 || !states[1].New || states[2].BindingID != 32 {
		t.Errorf("new pods: ids %d and %d, want 31 and 32 (30 is on a live connection)", states[1].BindingID, states[2].BindingID)
	}
	if maps.bindings[100].Gate != GateFailingOpen || maps.bindings[102] != (Binding{ID: 7, Gate: GateFailingOpen}) {
		t.Errorf("adopted bindings %+v %+v: the gate value must be kept, and a new container gets the current one", maps.bindings[100], maps.bindings[102])
	}
	if maps.bindings[200].Gate != GateFailingOpen || maps.bindings[300].Gate != GateRedirecting {
		t.Errorf("new bindings while the gate is open: allow %d, deny %d", maps.bindings[200].Gate, maps.bindings[300].Gate)
	}
	if _, ok := maps.bindings[900]; ok {
		t.Error("the binding of a pod that is gone was kept")
	}
	if len(maps.ai) != 0 {
		t.Errorf("ai_dsts %+v: entries of a binding that is gone must go", maps.ai)
	}
}

// A pod with no known cgroup is not bound, and is still reported.
func TestReconcilerPodWithoutCgroup(t *testing.T) {
	maps := newFakeMaps()
	r := NewReconciler(maps)
	states, err := r.Apply([]Pod{{UID: "x", Namespace: "ns", Name: "pod-x", Prepared: rootA, Policies: []Policy{policy("p", 1)}}}, rootA, Rotation{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Decision.Bound || states[0].BindingID != 0 || len(maps.bindings) != 0 {
		t.Errorf("states %+v bindings %+v", states, maps.bindings)
	}
}

func TestExemptSet(t *testing.T) {
	set, bad := ExemptSet(
		[]string{"10.244.0.0/16", "fd00:10:244::/56"},
		[]string{"10.96.0.1/12"},
		[]string{"192.168.1.10", "::ffff:192.168.1.10", "fe80::1"},
		[]string{"169.254.169.254", "not-a-range", "10.96.0.0/12"},
	)
	want := []netip.Prefix{
		netip.MustParsePrefix("10.96.0.0/12"),
		netip.MustParsePrefix("10.244.0.0/16"),
		netip.MustParsePrefix("169.254.169.254/32"),
		netip.MustParsePrefix("192.168.1.10/32"),
		netip.MustParsePrefix("fd00:10:244::/56"),
		netip.MustParsePrefix("fe80::1/128"),
	}
	if !reflect.DeepEqual(set, want) {
		t.Errorf("set %v\nwant %v", set, want)
	}
	if !reflect.DeepEqual(bad, []string{"not-a-range"}) {
		t.Errorf("bad %v", bad)
	}
}

func TestReadRotationAndNodeAddresses(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	if got, err := ReadRotation(ctx, client, "kubescape"); err != nil || got != (Rotation{}) {
		t.Errorf("no ConfigMap: %+v %v, want no rotation", got, err)
	}
	client = fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: TrustConfigMap},
		Data:       map[string]string{RotationKey: `{"currentRoot":"aa11","nextRoot":"bb22","windowEnds":null,"emergency":true}`},
	})
	got, err := ReadRotation(ctx, client, "kubescape")
	if err != nil || got != (Rotation{CurrentRoot: "aa11", NextRoot: "bb22", Emergency: true}) {
		t.Errorf("got %+v %v", got, err)
	}
	node := &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "192.168.1.10"},
		{Type: corev1.NodeHostName, Address: "node-1"},
		{Type: corev1.NodeExternalIP, Address: "198.51.100.7"},
	}}}
	if got := NodeAddresses(node); !reflect.DeepEqual(got, []string{"192.168.1.10", "198.51.100.7"}) {
		t.Errorf("node addresses %v", got)
	}
}

// While the node's root is not known, a bound pod stays bound and no other pod
// is bound.
func TestReconcilerRootUnknownKeepsBindings(t *testing.T) {
	maps := newFakeMaps()
	maps.bindings[100] = Binding{ID: 7}
	maps.bindings[101] = Binding{ID: 7}
	maps.bindings[102] = Binding{ID: 7}
	r := NewReconciler(maps)
	states, err := r.Apply([]Pod{pod("a", rootA, 100, policy("p", 2)), pod("b", rootA, 200, policy("p", 2))}, "", Rotation{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !states[0].Decision.Bound || states[0].BindingID != 7 || states[0].New || states[0].Decision.Reason != "" {
		t.Errorf("bound pod: %+v, want it kept", states[0])
	}
	if states[1].Decision.Bound || states[1].Decision.Reason != ReasonRootUnknown || states[1].Decision.NeedRestart {
		t.Errorf("unbound pod: %+v, want it left unbound, with no restart asked", states[1])
	}
	if len(maps.bindings) != 3 || maps.bindings[100].ID != 7 || maps.bindings[200].ID != 0 {
		t.Errorf("bindings %+v", maps.bindings)
	}
}

// While the node's root is not known, the rotation rule still unbinds a bound
// pod that lacks the next root.
func TestReconcilerRootUnknownKeepsRotationRule(t *testing.T) {
	maps := newFakeMaps()
	maps.bindings[101] = Binding{ID: 7}
	maps.bindings[201] = Binding{ID: 8}
	r := NewReconciler(maps)
	for name, rotation := range map[string]Rotation{
		"emergency":        {CurrentRoot: rootA, NextRoot: rootB, WindowEnds: now.Add(time.Hour), Emergency: true},
		"window has ended": {CurrentRoot: rootA, NextRoot: rootB, WindowEnds: now.Add(-time.Second)},
	} {
		maps.bindings[101], maps.bindings[201] = Binding{ID: 7}, Binding{ID: 8}
		states, err := r.Apply([]Pod{pod("old", rootA, 100, policy("p", 1)), pod("both", rootA+","+rootB, 200, policy("p", 1))}, "", rotation, now)
		if err != nil {
			t.Fatal(err)
		}
		if states[0].Decision.Bound || !states[0].Decision.NeedRestart || states[0].Decision.Reason != ReasonNextRootAbsent {
			t.Errorf("%s: pod without the next root %+v, want unbound and listed", name, states[0].Decision)
		}
		if !states[1].Decision.Bound || states[1].BindingID != 8 {
			t.Errorf("%s: pod with both roots %+v, want kept bound", name, states[1])
		}
		if _, ok := maps.bindings[101]; ok {
			t.Errorf("%s: the pod without the next root is still in bindings", name)
		}
	}
}

// A binding whose AI set cannot be written is not activated; the pod is
// reported not bound, keeps its id, and is New once the writes succeed.
func TestReconcilerAIWriteFailureHoldsTheBinding(t *testing.T) {
	maps := newFakeMaps()
	maps.failAI = map[uint32]bool{1: true}
	r := NewReconciler(maps)
	r.StaticAI = []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	pods := []Pod{pod("a", rootA, 100, policy("p", 1))}
	states, err := r.Apply(pods, rootA, Rotation{}, now)
	if !errors.Is(err, errInjected) {
		t.Fatalf("error %v, want the write failure", err)
	}
	if states[0].Decision.Bound || states[0].BindingID != 1 || len(maps.bindings) != 0 {
		t.Errorf("state %+v bindings %+v, want nothing bound", states[0], maps.bindings)
	}
	if _, ok := r.Owner(100); ok {
		t.Error("the lookup answers for a cgroup that is not bound")
	}
	maps.failAI = nil
	states, err = r.Apply(pods, rootA, Rotation{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !states[0].Decision.Bound || states[0].BindingID != 1 || !states[0].New || len(maps.bindings) != 3 {
		t.Errorf("after the retry: %+v, bindings %+v; want bound with id 1, New", states[0], maps.bindings)
	}
	states, _ = r.Apply(pods, rootA, Rotation{}, now)
	if states[0].New {
		t.Error("still New after every write succeeded")
	}
}

// A pod whose binding writes partly fail is New again on the next Apply, so
// its bind-time kill runs once all the entries are in place.
func TestReconcilerBindingWriteFailureKeepsThePodNew(t *testing.T) {
	maps := newFakeMaps()
	maps.failBinding = map[uint64]bool{102: true}
	r := NewReconciler(maps)
	pods := []Pod{pod("a", rootA, 100, policy("p", 1))}
	states, err := r.Apply(pods, rootA, Rotation{}, now)
	if !errors.Is(err, errInjected) {
		t.Fatalf("error %v", err)
	}
	if states[0].Decision.Bound {
		t.Errorf("reported bound with a container cgroup missing: %+v", states[0])
	}
	// Which cgroups were written before the failure depends on map order:
	// the lookup answers exactly for the ones that reached the kernel.
	for _, cgroup := range []uint64{100, 101, 102} {
		_, inKernel := maps.bindings[cgroup]
		if _, ok := r.Owner(cgroup); ok != inKernel {
			t.Errorf("cgroup %d: lookup answers %v, kernel entry %v", cgroup, ok, inKernel)
		}
	}
	if _, ok := maps.bindings[102]; ok {
		t.Error("the cgroup whose write failed has an entry")
	}
	maps.failBinding = nil
	states, _ = r.Apply(pods, rootA, Rotation{}, now)
	if !states[0].Decision.Bound || !states[0].New || states[0].BindingID != 1 {
		t.Errorf("after the retry: %+v, want bound, New, id 1", states[0])
	}
}

// Static addresses are the entries with expiry 0. One that is no longer
// configured leaves every live binding; entries other writers made stay.
func TestReconcilerRemovesStaleStaticAddresses(t *testing.T) {
	maps := newFakeMaps()
	old, kept, fed := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("198.51.100.5")
	maps.bindings[101] = Binding{ID: 7}
	maps.ai[AIDst{7, old}] = 0
	maps.ai[AIDst{7, kept}] = 0
	maps.ai[AIDst{7, fed}] = 123456 // written by another writer, with an expiry
	r := NewReconciler(maps)
	r.StaticAI = []netip.Addr{kept}
	if _, err := r.Apply([]Pod{pod("a", rootA, 100, policy("p", 1))}, rootA, Rotation{}, now); err != nil {
		t.Fatal(err)
	}
	want := map[AIDst]uint64{{7, kept}: 0, {7, fed}: 123456}
	if !reflect.DeepEqual(maps.ai, want) {
		t.Errorf("ai_dsts %v, want %v", maps.ai, want)
	}
}

// A container cgroup that gets its first entry makes the pod New, so the
// bind-time kill runs, unless the pod's own cgroup was already bound and
// covered it.
func TestReconcilerNewContainerCgroup(t *testing.T) {
	maps := newFakeMaps()
	r := NewReconciler(maps)
	noPodCgroup := pod("a", rootA, 0, policy("p", 1))
	noPodCgroup.Containers = map[string]uint64{"main": 11}
	covered := pod("b", rootA, 20, policy("p", 1))
	covered.Containers = map[string]uint64{"main": 21}
	if _, err := r.Apply([]Pod{noPodCgroup, covered}, rootA, Rotation{}, now); err != nil {
		t.Fatal(err)
	}
	states, _ := r.Apply([]Pod{noPodCgroup, covered}, rootA, Rotation{}, now)
	if states[0].New || states[1].New {
		t.Fatalf("nothing changed, yet New: %+v %+v", states[0], states[1])
	}
	noPodCgroup.Containers["side"] = 12
	covered.Containers["side"] = 22
	states, err := r.Apply([]Pod{noPodCgroup, covered}, rootA, Rotation{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !states[0].New {
		t.Errorf("a container cgroup with no bound pod cgroup above it: %+v, want New", states[0])
	}
	if states[1].New {
		t.Errorf("a container cgroup under a bound pod cgroup: %+v, want not New", states[1])
	}
}

// An adopted binding whose AI set cannot be written is reported not bound,
// though its entries stay in the kernel and the lookup answers for them.
func TestReconcilerAdoptedBindingAIFailure(t *testing.T) {
	maps := newFakeMaps()
	maps.bindings[100], maps.bindings[101], maps.bindings[102] = Binding{ID: 7}, Binding{ID: 7}, Binding{ID: 7}
	maps.failAI = map[uint32]bool{7: true}
	r := NewReconciler(maps)
	r.StaticAI = []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	states, err := r.Apply([]Pod{pod("a", rootA, 100, policy("p", 1))}, rootA, Rotation{}, now)
	if !errors.Is(err, errInjected) {
		t.Fatalf("error %v", err)
	}
	if states[0].Decision.Bound {
		t.Errorf("reported bound with its AI set not written: %+v", states[0])
	}
	if len(maps.bindings) != 3 {
		t.Errorf("bindings %v: the adopted entries must stay", maps.bindings)
	}
	if _, ok := r.Owner(101); !ok {
		t.Error("the lookup does not answer for a cgroup the kernel redirects")
	}
}
