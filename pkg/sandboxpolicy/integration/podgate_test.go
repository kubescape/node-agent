package integration

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// gateRecord is the fake backend's view of one pod: the ordering model of
// S2's node owner, reduced to what the pod gate relies on.
type gateRecord struct {
	plan   string
	seq    sandboxpolicy.Seq
	cgroup uint64
	bound  bool
	strict bool
}

// fakeGateBackend records every backend call, in order, and models the
// per-pod sequence rules (sandboxpolicy.Seq.Admits).
type fakeGateBackend struct {
	serviceTestBackend
	mu      sync.Mutex
	calls   []string
	binds   [][]sandboxpolicy.PodBinding
	seqs    []sandboxpolicy.Seq
	records map[types.UID]*gateRecord
	removed map[types.UID]sandboxpolicy.Seq
	gone    func(uint64) bool
	gate    *bool
	// markGate, when set, holds MarkPod until it is closed; markEntered
	// receives a value when MarkPod starts.
	markGate    chan struct{}
	markEntered chan struct{}
	markErr     error
	bindErr     error
	onBindAt    func()
}

func newFakeGateBackend() *fakeGateBackend {
	return &fakeGateBackend{records: map[types.UID]*gateRecord{}, removed: map[types.UID]sandboxpolicy.Seq{}}
}

func (b *fakeGateBackend) record(call string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, call)
}

func (b *fakeGateBackend) callNames() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.calls))
	for i, c := range b.calls {
		out[i], _, _ = strings.Cut(c, " ")
	}
	return out
}

func (b *fakeGateBackend) count(name string) int {
	n := 0
	for _, c := range b.callNames() {
		if c == name {
			n++
		}
	}
	return n
}

func planKeyOf(plan sandboxpolicy.Plan) string {
	var uids []string
	for _, p := range plan.Policies {
		uids = append(uids, string(p.Identity.UID)+string(p.Mode))
	}
	slices.Sort(uids)
	return strings.Join(uids, ",")
}

func strictPlan(plan sandboxpolicy.Plan) bool {
	return slices.ContainsFunc(plan.Policies, func(p sandboxpolicy.CompiledPolicy) bool { return p.Mode == api.ModeEnforce })
}

func (b *fakeGateBackend) BindPods(_ context.Context, pods []sandboxpolicy.PodBinding) error {
	b.record("BindPods")
	b.mu.Lock()
	defer b.mu.Unlock()
	b.binds = append(b.binds, pods)
	return b.bindErr
}

func (b *fakeGateBackend) MarkPod(_ context.Context, pod sandboxpolicy.PodBinding, seq sandboxpolicy.Seq) []sandboxpolicy.PodSectionResult {
	b.record(fmt.Sprintf("MarkPod %s %d/%d", pod.PodUID, seq.Config, seq.Input))
	b.mu.Lock()
	entered, hold := b.markEntered, b.markGate
	b.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if hold != nil {
		<-hold
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	res := sandboxpolicy.PodSectionResult{Section: sandboxpolicy.SectionPrivilege, Strict: strictPlan(pod.Plan), Err: b.markErr}
	if res.Err != nil {
		return []sandboxpolicy.PodSectionResult{res}
	}
	r := b.records[pod.PodUID]
	key := planKeyOf(pod.Plan)
	loosen := r != nil && r.strict && !strictPlan(pod.Plan)
	switch {
	case r == nil:
		if last, ok := b.removed[pod.PodUID]; ok && !seq.Admits(last, false) {
			res.Err = sandboxpolicy.ErrStaleSequence
			break
		}
		b.records[pod.PodUID] = &gateRecord{plan: key, seq: seq, cgroup: pod.CgroupID, strict: strictPlan(pod.Plan)}
	case r.plan == key:
	case !seq.Admits(r.seq, loosen):
		res.Err = sandboxpolicy.ErrStaleSequence
	default:
		r.plan, r.strict, r.bound = key, strictPlan(pod.Plan), false
		if seq.Compare(r.seq) == sandboxpolicy.SeqNewer {
			r.seq = seq
		}
	}
	return []sandboxpolicy.PodSectionResult{res}
}

func (b *fakeGateBackend) EnsurePodBound(_ context.Context, uid types.UID, plan sandboxpolicy.Plan) []sandboxpolicy.PodSectionResult {
	b.record("EnsurePodBound " + string(uid))
	b.mu.Lock()
	defer b.mu.Unlock()
	res := sandboxpolicy.PodSectionResult{Section: sandboxpolicy.SectionPrivilege, Strict: strictPlan(plan)}
	if r := b.records[uid]; r != nil {
		r.bound = true
	} else {
		res.Err = errors.New("no record")
	}
	return []sandboxpolicy.PodSectionResult{res}
}

func (b *fakeGateBackend) ConfirmPod(uid types.UID, cgroupID uint64, plan sandboxpolicy.Plan) []sandboxpolicy.PodSectionConfirmation {
	b.record("ConfirmPod " + string(uid))
	b.mu.Lock()
	defer b.mu.Unlock()
	c := sandboxpolicy.PodSectionConfirmation{Section: sandboxpolicy.SectionPrivilege, Strict: strictPlan(plan)}
	if r := b.records[uid]; r != nil && r.cgroup == cgroupID && r.plan == planKeyOf(plan) {
		c.State = sandboxpolicy.PodSectionPending
		if r.bound {
			c.State = sandboxpolicy.PodSectionConfirmed
		}
	}
	return []sandboxpolicy.PodSectionConfirmation{c}
}

func (b *fakeGateBackend) ReleasePod(_ context.Context, uid types.UID, _ uint64) error {
	b.record("ReleasePod " + string(uid))
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.records, uid)
	delete(b.removed, uid) // ReleasePod forgets the pod's order
	return nil
}

func (b *fakeGateBackend) UnmarkPod(_ context.Context, uid types.UID, _ uint64, seq sandboxpolicy.Seq) error {
	b.record(fmt.Sprintf("UnmarkPod %s %d/%d", uid, seq.Config, seq.Input))
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.records[uid]
	if r == nil || !seq.Admits(r.seq, true) {
		return fmt.Errorf("privilege pod %s: %w", uid, sandboxpolicy.ErrStaleSequence)
	}
	delete(b.records, uid)
	b.removed[uid] = seq
	return nil
}

func (b *fakeGateBackend) BindPodsAt(_ context.Context, pods []sandboxpolicy.PodBinding, seq sandboxpolicy.Seq) error {
	b.record(fmt.Sprintf("BindPodsAt %d/%d", seq.Config, seq.Input))
	if b.onBindAt != nil {
		b.onBindAt()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.binds = append(b.binds, pods)
	b.seqs = append(b.seqs, seq)
	var errs []error
	for _, p := range pods {
		key := planKeyOf(p.Plan)
		r := b.records[p.PodUID]
		switch {
		case r == nil:
			b.records[p.PodUID] = &gateRecord{plan: key, seq: seq, cgroup: p.CgroupID, bound: true, strict: strictPlan(p.Plan)}
		case r.plan == key:
			r.bound = true // sequence-neutral
		case seq.Admits(r.seq, r.strict && !strictPlan(p.Plan)):
			r.plan, r.strict, r.bound, r.seq = key, strictPlan(p.Plan), true, seq
		default:
			errs = append(errs, fmt.Errorf("privilege pod %s: %w", p.PodUID, sandboxpolicy.ErrStaleSequence))
		}
	}
	return errors.Join(append(errs, b.bindErr)...)
}

func (b *fakeGateBackend) SetStartGate(enabled bool) {
	b.record(fmt.Sprintf("SetStartGate %v", enabled))
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gate = &enabled
}

func (b *fakeGateBackend) SetCgroupGone(gone func(uint64) bool) {
	b.record("SetCgroupGone")
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gone = gone
}

func (b *fakeGateBackend) rec(uid types.UID) *gateRecord {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r := b.records[uid]; r != nil {
		cp := *r
		return &cp
	}
	return nil
}

func gatePolicy(uid types.UID, mode api.PolicyMode) sandboxpolicy.CompiledPolicy {
	return sandboxpolicy.CompiledPolicy{Identity: sandboxpolicy.PolicyIdentity{UID: uid, Kind: "SandboxPolicy", Namespace: "ns", Name: string(uid)}, Mode: mode, Privilege: &api.PrivilegeSection{}}
}

func selected(seq sandboxpolicy.Seq, policies ...sandboxpolicy.CompiledPolicy) sandboxpolicy.PodClassification {
	plan := sandboxpolicy.Plan{Policies: policies}
	return sandboxpolicy.PodClassification{Class: sandboxpolicy.PodSelected, Seq: seq, Strict: strictPlan(plan),
		Sections: map[string]sandboxpolicy.SectionPlan{sandboxpolicy.SectionPrivilege: {Plan: plan, Digest: planKeyOf(plan), Strict: strictPlan(plan)}}}
}

func testSandbox(id string) gateSandbox {
	return gateSandbox{UID: "pod-uid", Namespace: "ns", Name: "pod", SandboxID: id, CgroupID: 77, CgroupPath: "/kubepods/podpod_uid"}
}

func soon() time.Time { return time.Now().Add(5 * time.Second) }

func noContextError(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("a reply wraps a context error: %v", err)
	}
}

// TestPodGateJoinMarkAndHold: a Selected pod is marked at its
// classification's sequence, then held until the bind is confirmed.
func TestPodGateJoinMarkAndHold(t *testing.T) {
	b := newFakeGateBackend()
	g := newPodGate(t.Context(), b, nil)
	c := selected(sandboxpolicy.Seq{Config: 2, Input: 3}, gatePolicy("p1", api.ModeEnforce))
	res, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, soon())
	if err != nil || len(res) != 1 || res[0].Err != nil || !res[0].Strict {
		t.Fatalf("mark: %+v %v", res, err)
	}
	conf, err := g.HoldUntilConfirmed(t.Context(), "pod-uid", "sb1", c, soon())
	if err != nil || len(conf) != 1 || conf[0].State != sandboxpolicy.PodSectionConfirmed {
		t.Fatalf("hold: %+v %v", conf, err)
	}
	if got := b.callNames(); !slices.Equal(got, []string{"MarkPod", "EnsurePodBound", "ConfirmPod"}) {
		t.Fatalf("calls: %v", got)
	}
	// Not Selected, or no deadline: no backend call.
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), sandboxpolicy.PodClassification{Class: sandboxpolicy.PodUnselected}, soon()); !errors.Is(err, errNotSelected) {
		t.Fatalf("unselected: %v", err)
	}
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, time.Time{}); !errors.Is(err, errNoWorkDeadline) {
		t.Fatalf("no deadline: %v", err)
	}
	if _, err := g.HoldUntilConfirmed(t.Context(), "pod-uid", "other", c, soon()); !errors.Is(err, errNotJoined) {
		t.Fatalf("hold of an unknown sandbox: %v", err)
	}
	g.wait()
	if b.count("MarkPod") != 1 {
		t.Fatalf("refused calls reached the backend: %v", b.callNames())
	}
}

// TestPodGateMergeKeepsNRIEntries: bindPodPlans' set is the API's with the
// NRI entries merged in; an informer miss never removes an entry.
func TestPodGateMergeKeepsNRIEntries(t *testing.T) {
	b := newFakeGateBackend()
	g := newPodGate(t.Context(), b, nil)
	markSeq := sandboxpolicy.Seq{Config: 4, Input: 4}
	c := selected(markSeq, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, soon()); err != nil {
		t.Fatal(err)
	}
	api1 := sandboxpolicy.PodBinding{PodUID: "api-pod", CgroupID: 5, Plan: sandboxpolicy.Plan{Policies: []sandboxpolicy.CompiledPolicy{gatePolicy("p2", api.ModeAudit)}}}
	// An older, equal or incomparable API sequence: the entry is added
	// with its plan (a same-plan bind is sequence-neutral).
	for _, seq := range []sandboxpolicy.Seq{{Config: 3, Input: 4}, markSeq, {Config: 5, Input: 3}} {
		out, _ := g.merge([]sandboxpolicy.PodBinding{api1}, seq, func(types.UID, string) bool { return true })
		if len(out) != 2 || out[1].PodUID != "pod-uid" || out[1].CgroupID != 77 || planKeyOf(out[1].Plan) != planKeyOf(c.Sections[sandboxpolicy.SectionPrivilege].Plan) || !out[1].ContainersStarted {
			t.Fatalf("merge at %+v: %+v", seq, out)
		}
	}
	// A newer API sequence: the entry's plan may be older than the
	// backend's, so the pod is left out (missing never removes it).
	out, _ := g.merge([]sandboxpolicy.PodBinding{api1}, sandboxpolicy.Seq{Config: 4, Input: 9}, nil)
	if len(out) != 1 || out[0].PodUID != "api-pod" {
		t.Fatalf("merge at a newer sequence: %+v", out)
	}
	// The API's entry for a joined pod wins.
	apiOwn := sandboxpolicy.PodBinding{PodUID: "pod-uid", CgroupID: 77, Plan: sandboxpolicy.Plan{Policies: []sandboxpolicy.CompiledPolicy{gatePolicy("p3", api.ModeEnforce)}}}
	out, _ = g.merge([]sandboxpolicy.PodBinding{apiOwn}, markSeq, nil)
	if len(out) != 1 || planKeyOf(out[0].Plan) != planKeyOf(apiOwn.Plan) {
		t.Fatalf("the API entry must win: %+v", out)
	}
	// Many refreshes that miss the pod (informer miss, failed lookup):
	// the entry stays.
	for range 50 {
		g.merge(nil, sandboxpolicy.Seq{Config: 9, Input: 9}, nil)
	}
	g.podMu.Lock()
	kept := g.pods["pod-uid"] != nil
	g.podMu.Unlock()
	if !kept {
		t.Fatal("an informer miss removed an NRI entry")
	}
	// An unmarked entry carries no plan: never added.
	if err := g.Unmark(t.Context(), testSandbox("sb1"), sandboxpolicy.Seq{Config: 5, Input: 5}, soon()); err != nil {
		t.Fatal(err)
	}
	if out, _ := g.merge(nil, sandboxpolicy.Seq{Config: 1, Input: 1}, nil); len(out) != 0 {
		t.Fatalf("an unmarked pod was merged: %+v", out)
	}
	g.wait()
}

// TestPodGateTombstones: a removed sandbox is never marked again, and the
// last removal releases the pod; a sandbox that is not the last does not.
func TestPodGateTombstones(t *testing.T) {
	b := newFakeGateBackend()
	g := newPodGate(t.Context(), b, nil)
	c := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce))
	for _, id := range []string{"sb1", "sb2"} {
		if _, err := g.JoinAndMark(t.Context(), testSandbox(id), c, soon()); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.ReleaseSandbox(t.Context(), testSandbox("sb1"), soon()); err != nil {
		t.Fatal(err)
	}
	if b.count("ReleasePod") != 0 {
		t.Fatal("a sandbox that is not the pod's last released the pod")
	}
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, soon()); !errors.Is(err, errSandboxRemoved) {
		t.Fatalf("a tombstoned sandbox was marked: %v", err)
	}
	if err := g.Unmark(t.Context(), testSandbox("sb1"), sandboxpolicy.Seq{Config: 9, Input: 9}, soon()); !errors.Is(err, errSandboxRemoved) {
		t.Fatalf("a tombstoned sandbox was unmarked: %v", err)
	}
	if err := g.ReleaseSandbox(t.Context(), testSandbox("sb2"), soon()); err != nil {
		t.Fatal(err)
	}
	if b.count("ReleasePod") != 1 || b.rec("pod-uid") != nil {
		t.Fatalf("the last removal must release the pod: %v", b.callNames())
	}
	if _, err := g.HoldUntilConfirmed(t.Context(), "pod-uid", "sb2", c, soon()); !errors.Is(err, errSandboxRemoved) {
		t.Fatalf("hold of a removed sandbox: %v", err)
	}
	// A released pod is left out of the API's set.
	out, _ := g.merge([]sandboxpolicy.PodBinding{{PodUID: "pod-uid", CgroupID: 77, Plan: c.Sections[sandboxpolicy.SectionPrivilege].Plan}}, sandboxpolicy.Seq{Config: 9, Input: 9}, nil)
	if len(out) != 0 {
		t.Fatalf("the API path would bind a released pod again: %+v", out)
	}
	g.wait()
	if b.count("MarkPod") != 2 {
		t.Fatalf("calls: %v", b.callNames())
	}
}

// TestPodGateStaleWorkerAfterRelease: a mark in flight when its sandbox is
// removed lands before the release, and a mark queued behind it never runs.
func TestPodGateStaleWorkerAfterRelease(t *testing.T) {
	b := newFakeGateBackend()
	b.markGate, b.markEntered = make(chan struct{}), make(chan struct{}, 4)
	g := newPodGate(t.Context(), b, nil)
	c := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce))
	short := func() time.Time { return time.Now().Add(20 * time.Millisecond) }
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, short()); !errors.Is(err, errWorkDeadline) {
		t.Fatalf("held mark: %v", err)
	}
	<-b.markEntered
	// A second mark of the same sandbox at a newer sequence queues behind
	// the one in flight.
	c2 := selected(sandboxpolicy.Seq{Config: 2, Input: 2}, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c2, short()); !errors.Is(err, errWorkDeadline) {
		t.Fatalf("queued mark: %v", err)
	}
	released := make(chan error, 1)
	go func() { released <- g.ReleaseSandbox(t.Context(), testSandbox("sb1"), soon()) }()
	// The tombstone is set before the release job runs.
	for {
		g.podMu.Lock()
		done := g.tombstonedLocked("sb1")
		g.podMu.Unlock()
		if done {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(b.markGate)
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	g.wait()
	if got := b.callNames(); !slices.Equal(got, []string{"MarkPod", "ReleasePod"}) {
		t.Fatalf("calls: %v", got)
	}
	if b.rec("pod-uid") != nil {
		t.Fatal("a stale worker re-marked a removed sandbox")
	}
}

// TestPodGateSandboxRecreation: a new sandbox of a released pod starts
// fresh, whatever the old sandbox's sequence.
func TestPodGateSandboxRecreation(t *testing.T) {
	b := newFakeGateBackend()
	g := newPodGate(t.Context(), b, nil)
	old := selected(sandboxpolicy.Seq{Config: 7, Input: 7}, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), old, soon()); err != nil {
		t.Fatal(err)
	}
	if err := g.ReleaseSandbox(t.Context(), testSandbox("sb1"), soon()); err != nil {
		t.Fatal(err)
	}
	fresh := selected(sandboxpolicy.Seq{Config: 7, Input: 6}, gatePolicy("p2", api.ModeAudit))
	sb := testSandbox("sb2")
	sb.CgroupID = 78
	res, err := g.JoinAndMark(t.Context(), sb, fresh, soon())
	if err != nil || len(res) != 1 || res[0].Err != nil {
		t.Fatalf("recreated sandbox: %+v %v", res, err)
	}
	g.podMu.Lock()
	e := g.pods["pod-uid"]
	g.podMu.Unlock()
	if e == nil || e.released || e.seq != fresh.Seq || e.sandbox.CgroupID != 78 || e.sandboxes["sb2"] != 78 || len(e.sandboxes) != 1 {
		t.Fatalf("the recreated sandbox did not start fresh: %+v", e)
	}
	if r := b.rec("pod-uid"); r == nil || r.seq != fresh.Seq || r.cgroup != 78 {
		t.Fatalf("backend record: %+v", r)
	}
	g.wait()
}

// TestPodGateDeadlineAbandonment: the handler replies at its deadline
// without a context error; the worker's late write still applies when its
// sequence is current, and is refused by sequence when a newer write came.
func TestPodGateDeadlineAbandonment(t *testing.T) {
	t.Run("late write applies", func(t *testing.T) {
		b := newFakeGateBackend()
		b.markGate, b.markEntered = make(chan struct{}), make(chan struct{}, 1)
		g := newPodGate(t.Context(), b, nil)
		c := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce))
		_, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, time.Now().Add(20*time.Millisecond))
		if !errors.Is(err, errWorkDeadline) {
			t.Fatalf("deadline: %v", err)
		}
		noContextError(t, err)
		<-b.markEntered
		close(b.markGate)
		g.wait()
		if r := b.rec("pod-uid"); r == nil || r.seq != c.Seq {
			t.Fatalf("the abandoned worker's write did not apply: %+v", r)
		}
		// The handler's retry finds the write done.
		res, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, soon())
		if err != nil || len(res) != 1 || res[0].Err != nil {
			t.Fatalf("retry: %+v %v", res, err)
		}
		g.wait()
	})
	t.Run("late write refused by sequence", func(t *testing.T) {
		b := newFakeGateBackend()
		b.markGate, b.markEntered = make(chan struct{}), make(chan struct{}, 2)
		g := newPodGate(t.Context(), b, nil)
		c := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce))
		if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, time.Now().Add(20*time.Millisecond)); !errors.Is(err, errWorkDeadline) {
			t.Fatalf("deadline: %v", err)
		}
		<-b.markEntered
		// The API path writes a newer plan while the mark is held.
		newer := sandboxpolicy.Seq{Config: 2, Input: 2}
		apiPlan := sandboxpolicy.Plan{Policies: []sandboxpolicy.CompiledPolicy{gatePolicy("p2", api.ModeEnforce)}}
		if err := b.BindPodsAt(t.Context(), []sandboxpolicy.PodBinding{{PodUID: "pod-uid", CgroupID: 77, Plan: apiPlan}}, newer); err != nil {
			t.Fatal(err)
		}
		close(b.markGate)
		g.wait()
		if r := b.rec("pod-uid"); r == nil || r.plan != planKeyOf(apiPlan) || r.seq != newer {
			t.Fatalf("a stale late write overwrote a newer one: %+v", r)
		}
		// A retry at the old sequence gets the refusal, as a section result.
		res, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, soon())
		if err != nil || len(res) != 1 || !errors.Is(res[0].Err, sandboxpolicy.ErrStaleSequence) {
			t.Fatalf("retry at the old sequence: %+v %v", res, err)
		}
		g.wait()
	})
	t.Run("handler context and backend context errors", func(t *testing.T) {
		b := newFakeGateBackend()
		b.markGate, b.markEntered = make(chan struct{}), make(chan struct{}, 1)
		g := newPodGate(t.Context(), b, nil)
		c := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := g.JoinAndMark(ctx, testSandbox("sb1"), c, soon())
		if !errors.Is(err, errHandlerGone) {
			t.Fatalf("canceled handler: %v", err)
		}
		noContextError(t, err)
		<-b.markEntered
		b.mu.Lock()
		b.markErr = fmt.Errorf("instance: %w", context.Canceled)
		b.mu.Unlock()
		close(b.markGate)
		g.wait()
		res, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), selected(sandboxpolicy.Seq{Config: 2, Input: 2}, gatePolicy("p1", api.ModeEnforce)), soon())
		if err != nil || len(res) != 1 || res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "canceled") {
			t.Fatalf("backend error: %+v %v", res, err)
		}
		noContextError(t, res[0].Err)
		g.wait()
	})
	t.Run("hold deadline returns the last confirmations", func(t *testing.T) {
		b := newFakeGateBackend()
		g := newPodGate(t.Context(), b, nil)
		c := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce))
		if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, soon()); err != nil {
			t.Fatal(err)
		}
		// The caller's classification has another plan: never confirmed.
		other := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p9", api.ModeEnforce))
		conf, err := g.HoldUntilConfirmed(t.Context(), "pod-uid", "sb1", other, time.Now().Add(60*time.Millisecond))
		if !errors.Is(err, errWorkDeadline) || len(conf) != 1 || conf[0].State != sandboxpolicy.PodSectionFaulted {
			t.Fatalf("hold: %+v %v", conf, err)
		}
		noContextError(t, err)
		if b.count("EnsurePodBound") < 2 {
			t.Fatalf("the hold did not retry: %v", b.callNames())
		}
		g.wait()
	})
}

// TestPodGateUnmarkStaleRetryIsDone: S2 review v6 note 1.
func TestPodGateUnmarkStaleRetryIsDone(t *testing.T) {
	b := newFakeGateBackend()
	g := newPodGate(t.Context(), b, nil)
	c := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, soon()); err != nil {
		t.Fatal(err)
	}
	// An equal sequence never loosens: refused, and not "done".
	if err := g.Unmark(t.Context(), testSandbox("sb1"), c.Seq, soon()); !errors.Is(err, sandboxpolicy.ErrStaleSequence) {
		t.Fatalf("equal-sequence unmark: %v", err)
	}
	at := sandboxpolicy.Seq{Config: 3, Input: 3}
	if err := g.Unmark(t.Context(), testSandbox("sb1"), at, soon()); err != nil {
		t.Fatal(err)
	}
	// The backend refuses a retry after the removal; the gate reads it as
	// done (equal or older sequence).
	for _, retry := range []sandboxpolicy.Seq{at, {Config: 2, Input: 3}} {
		if err := g.Unmark(t.Context(), testSandbox("sb1"), retry, soon()); err != nil {
			t.Fatalf("retry at %+v after a completed unmark: %v", retry, err)
		}
	}
	if b.count("UnmarkPod") != 4 {
		t.Fatalf("calls: %v", b.callNames())
	}
	// A newer mark clears it: a later stale refusal is an error again.
	c2 := selected(sandboxpolicy.Seq{Config: 4, Input: 4}, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c2, soon()); err != nil {
		t.Fatal(err)
	}
	if err := g.Unmark(t.Context(), testSandbox("sb1"), at, soon()); !errors.Is(err, sandboxpolicy.ErrStaleSequence) {
		t.Fatalf("an unmark older than a newer mark must stay refused: %v", err)
	}
	g.wait()
}

// gateTestService builds a service with one scheduled Strict privilege pod
// (pod-uid, cgroup 77) listed through a fake clientset, a controller that
// loaded its policy, and backend.
func gateTestService(t *testing.T, backend *fakeGateBackend) *Service {
	t.Helper()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{sandboxpolicy.PolicyGVR: "SandboxPolicyList", sandboxpolicy.ClusterPolicyGVR: "ClusterSandboxPolicyList", sandboxpolicy.ClassesGVR: "SandboxPolicyClassesList"})
	p := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.SchemeGroupVersion.String(), "kind": "SandboxPolicy", "metadata": map[string]any{"name": "priv", "namespace": "ns", "uid": "policy-uid", "generation": int64(1)}, "spec": map[string]any{"selector": map[string]any{"podSelector": map[string]any{}}, "mode": "enforce", "containers": []any{"*"}, "privilege": map[string]any{"default": "allow", "rules": []any{map[string]any{"name": "no-chroot", "action": "deny", "target": map[string]any{"syscall": []any{"chroot"}}}}}}}}
	if _, err := client.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Create(t.Context(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	controller, err := sandboxpolicy.NewController(client, backend, nil, nil, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.InitialSync(t.Context()); err != nil {
		t.Fatal(err)
	}
	kube := kubefake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid"}, Spec: corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "app"}}},
			Status: corev1.PodStatus{Phase: corev1.PodPending, QOSClass: corev1.PodQOSBestEffort}})
	containers := &containercollection.ContainerCollection{}
	running := &containercollection.Container{CgroupID: 500, CgroupV2: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podother_uid.slice/cri-containerd-x.scope"}
	running.Runtime.ContainerID = "x"
	running.K8s.PodUID = "other-uid"
	containers.AddContainer(running)
	want := "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice"
	return &Service{Controller: controller, backend: backend, options: ServiceOptions{Kubernetes: kube, Containers: containers, NodeName: "node"},
		// Main's path without informers reads the pods of the last slot
		// preparation; the gate's reads them inside its capture.
		scheduled: []sandboxpolicy.Binding{{PodUID: "pod-uid", Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular"}},
		qos:       map[types.UID]corev1.PodQOSClass{"pod-uid": corev1.PodQOSBestEffort},
		podCgroupID: func(path string) (uint64, error) {
			if path != want {
				return 0, errors.New("no such cgroup")
			}
			return 77, nil
		}}
}

// mainSequence runs main's pod binding steps: two bindPods (as one refresh
// does), a poll, and a bindPods with a failing backend.
func mainSequence(t *testing.T, s *Service, setErr func(error)) {
	t.Helper()
	s.bindPods(t.Context())
	s.inputEpoch.Add(1)
	s.bindPods(t.Context())
	s.pollPods(t.Context())
	setErr(errors.New("busy"))
	s.bindPods(t.Context())
	s.pollPods(t.Context())
	setErr(nil)
}

// TestServiceStartGateOffCallSequenceUnchanged: with the gate off, a backend
// that has the pod gate gets exactly main's calls: BindPods, with the pods
// main's backend gets, and nothing of the gate.
func TestServiceStartGateOffCallSequenceUnchanged(t *testing.T) {
	gated := newFakeGateBackend()
	s := gateTestService(t, gated)
	mainSequence(t, s, func(err error) { gated.bindErr = err })

	plain := &podBinderBackend{}
	m := gateTestService(t, newFakeGateBackend())
	m.backend = plain
	mainSequence(t, m, func(err error) { plain.err = err })

	if got := gated.callNames(); !slices.Equal(got, []string{"BindPods", "BindPods", "BindPods", "BindPods", "BindPods"}) {
		t.Fatalf("gate off: backend calls %v", got)
	}
	if len(gated.binds) != len(plain.pods) {
		t.Fatalf("gate off: %d BindPods calls, main %d", len(gated.binds), len(plain.pods))
	}
	for i := range plain.pods {
		if !reflect.DeepEqual(gated.binds[i], plain.pods[i]) {
			t.Fatalf("call %d: gate off %+v, main %+v", i, gated.binds[i], plain.pods[i])
		}
	}
	if len(gated.binds[0]) != 1 || gated.binds[0][0].CgroupID != 77 {
		t.Fatalf("the scheduled pod was not bound: %+v", gated.binds[0])
	}
	if gated.gate != nil || gated.gone != nil || s.podSeq != nil {
		t.Fatal("gate off touched the start gate")
	}
}

func handleID(h unix.FileHandle) uint64 { return binary.NativeEndian.Uint64(h.Bytes()) }

// startGateSyscalls is a cgroup v2 root (ID 1) whose gone cgroups are
// listed (and every ID with bit 63, the self-test's negative probe), with
// CAP_DAC_READ_SEARCH, no live path, and a clock that moves one second per
// check (so the second ESTALE proves a cgroup gone).
func startGateSyscalls(gone ...uint64) handleSyscalls {
	var mu sync.Mutex
	clock := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	return handleSyscalls{
		openRoot:    func(string) (int, error) { return 100, nil },
		fstatfsType: func(int) (int64, error) { return 0x63677270, nil }, // CGROUP2_SUPER_MAGIC
		openByHandle: func(_ int, h unix.FileHandle, _ int) (int, error) {
			if slices.Contains(gone, handleID(h)) || handleID(h)&(1<<63) != 0 {
				return -1, unix.ESTALE
			}
			return 101, nil
		},
		pathID:        func(string, string) (uint64, error) { return 0, unix.ENOENT },
		handleOf:      func(int) (unix.FileHandle, error) { return cgroupHandle(1), nil },
		dacReadSearch: func() (bool, error) { return true, nil },
		close:         func(int) error { return nil },
		now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			clock = clock.Add(time.Second)
			return clock
		},
	}
}

// TestServiceStartGateOnBindsAtSequence: with the gate on, the refresh calls
// BindPodsAt with (configSeq of the plans, input epoch read around the pod
// list), never BindPods; the poll reuses that older sequence.
func TestServiceStartGateOnBindsAtSequence(t *testing.T) {
	b := newFakeGateBackend()
	s := gateTestService(t, b)
	s.inputEpoch.Store(5)
	if err := s.enableStartGate(t.Context(), startGateSyscalls()); err != nil {
		t.Fatal(err)
	}
	_, configSeq, ok := s.Controller.PodPlansAt(nil)
	if !ok || configSeq == 0 {
		t.Fatalf("no snapshot: %d %v", configSeq, ok)
	}
	s.bindPods(t.Context())
	s.inputEpoch.Add(3)
	s.pollPods(t.Context())
	if got := b.callNames(); !slices.Equal(got, []string{"SetCgroupGone", "SetStartGate", "BindPodsAt", "BindPodsAt"}) {
		t.Fatalf("gate on: backend calls %v", got)
	}
	want := sandboxpolicy.Seq{Config: configSeq, Input: 5}
	if b.seqs[0] != want || b.seqs[1] != want {
		t.Fatalf("sequences %+v, want %+v twice", b.seqs, want)
	}
	if len(b.binds[0]) != 1 || b.binds[0][0].CgroupID != 77 {
		t.Fatalf("bind: %+v", b.binds[0])
	}
	s.bindPods(t.Context())
	if got := b.seqs[2]; got != (sandboxpolicy.Seq{Config: configSeq, Input: 8}) {
		t.Fatalf("a new refresh captures a new epoch: %+v", got)
	}
	// Design §3 item 4: the poll's older sequence binds a mark to its own
	// plan, and is refused a different plan.
	g := s.gate.Load()
	newer := sandboxpolicy.Seq{Config: configSeq, Input: 20}
	nri := gateSandbox{UID: "nri-pod", Namespace: "ns", Name: "nri", SandboxID: "sb9", CgroupID: 90}
	if _, err := g.JoinAndMark(t.Context(), nri, selected(newer, gatePolicy("p1", api.ModeEnforce)), soon()); err != nil {
		t.Fatal(err)
	}
	other := selected(newer, gatePolicy("p7", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), other, soon()); err != nil {
		t.Fatal(err)
	}
	var reported []error
	s.options.OnError = func(err error) { reported = append(reported, err) }
	s.pollPods(t.Context())
	if r := b.rec("nri-pod"); r == nil || !r.bound {
		t.Fatalf("the poll did not bind a mark to its own plan: %+v", r)
	}
	if r := b.rec("pod-uid"); r == nil || r.plan != planKeyOf(other.Sections[sandboxpolicy.SectionPrivilege].Plan) || r.seq != newer {
		t.Fatalf("the poll's older sequence changed a newer mark's plan: %+v", r)
	}
	if len(reported) != 1 || !errors.Is(reported[0], sandboxpolicy.ErrStaleSequence) {
		t.Fatalf("the refused write must be reported as stale: %v", reported)
	}
	g.wait()
}

// TestServiceStartGateMergeAndInformerMiss: a pod the API path does not
// list (here: the clientset lost it) is still sent from the NRI set, and
// stays in the set.
func TestServiceStartGateMergeAndInformerMiss(t *testing.T) {
	b := newFakeGateBackend()
	s := gateTestService(t, b)
	if err := s.enableStartGate(t.Context(), startGateSyscalls()); err != nil {
		t.Fatal(err)
	}
	g := s.gate.Load()
	nri := gateSandbox{UID: "nri-pod", Namespace: "ns", Name: "nri", SandboxID: "sb9", CgroupID: 90, CgroupPath: "/kubepods/podnri"}
	c := selected(sandboxpolicy.Seq{Config: 100, Input: 100}, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), nri, c, soon()); err != nil {
		t.Fatal(err)
	}
	s.bindPods(t.Context())
	last := b.binds[len(b.binds)-1]
	if len(last) != 2 || last[0].PodUID != "nri-pod" || last[1].PodUID != "pod-uid" {
		t.Fatalf("merged set: %+v", last)
	}
	s.mu.RLock()
	_, indexed := s.podCgroups[90]
	s.mu.RUnlock()
	if !indexed {
		t.Fatal("the NRI pod's cgroup is not in the verdict index")
	}
	if r := b.rec("nri-pod"); r == nil || !r.bound {
		t.Fatalf("the NRI pod's mark did not move to its slot: %+v", r)
	}
	// The API path no longer lists the pod (its namespace is not cached):
	// the NRI pod is still sent, and its entry stays.
	if err := s.options.Kubernetes.(*kubefake.Clientset).Tracker().Delete(corev1.SchemeGroupVersion.WithResource("namespaces"), "", "ns", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	calls := len(b.binds)
	s.bindPods(t.Context())
	if len(b.binds) != calls+1 || len(b.binds[calls]) != 1 || b.binds[calls][0].PodUID != "nri-pod" {
		t.Fatalf("an informer miss: %+v", b.binds[calls:])
	}
	g.podMu.Lock()
	kept := g.pods["nri-pod"] != nil
	g.podMu.Unlock()
	if !kept {
		t.Fatal("an informer miss removed the NRI entry")
	}
	g.wait()
}

// TestServiceStartGateStaleBindIsNotNothingChanged: S2 review v6 note 2. A
// BindPodsAt that returns ErrStaleSequence still releases a pod released
// during the call, and the next poll calls the backend again.
func TestServiceStartGateStaleBindIsNotNothingChanged(t *testing.T) {
	b := newFakeGateBackend()
	s := gateTestService(t, b)
	if err := s.enableStartGate(t.Context(), startGateSyscalls()); err != nil {
		t.Fatal(err)
	}
	g := s.gate.Load()
	c := selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce))
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), c, soon()); err != nil {
		t.Fatal(err)
	}
	reports := 0
	s.options.OnError = func(error) { reports++ }
	// The pod's last sandbox is removed while BindPodsAt runs, and the call
	// reports a stale write.
	b.onBindAt = func() {
		b.onBindAt = nil
		if err := g.ReleaseSandbox(t.Context(), testSandbox("sb1"), soon()); err != nil {
			t.Error(err)
		}
		b.mu.Lock()
		b.bindErr = fmt.Errorf("privilege pod ns/pod: %w", sandboxpolicy.ErrStaleSequence)
		b.mu.Unlock()
	}
	s.bindPods(t.Context())
	g.wait()
	if got := b.count("ReleasePod"); got != 2 {
		t.Fatalf("a release during a stale BindPodsAt must be repeated after it: %d (%v)", got, b.callNames())
	}
	if b.rec("pod-uid") != nil {
		t.Fatal("the API path bound a released pod again")
	}
	if reports != 1 {
		t.Fatalf("the stale write must be reported: %d", reports)
	}
	before := b.count("BindPodsAt")
	s.pollPods(t.Context())
	if b.count("BindPodsAt") != before+1 {
		t.Fatal("a stale result stopped the next poll")
	}
	// The released pod is no longer sent.
	if last := b.binds[len(b.binds)-1]; len(last) != 0 {
		t.Fatalf("poll after release: %+v", last)
	}
}

// TestServiceStartGateCgroupGoneWiring: only enableStartGate wires the
// cgroup-gone proof, by cgroup ID; a root that is not cgroup v2 leaves the
// gate off; the proof prunes the set.
func TestServiceStartGateCgroupGoneWiring(t *testing.T) {
	b := newFakeGateBackend()
	s := gateTestService(t, b)
	bad := startGateSyscalls()
	bad.fstatfsType = func(int) (int64, error) { return 0x27e0eb, nil } // cgroup v1
	closed := 0
	bad.close = func(int) error { closed++; return nil }
	if err := s.enableStartGate(t.Context(), bad); err == nil || s.gate.Load() != nil || closed != 1 {
		t.Fatalf("a cgroup v1 root must leave the gate off: %v closed=%d", err, closed)
	}
	if len(b.callNames()) != 0 {
		t.Fatalf("a failed enable reached the backend: %v", b.callNames())
	}
	if err := s.enableStartGate(t.Context(), startGateSyscalls(77)); err != nil {
		t.Fatal(err)
	}
	if b.gone == nil || b.gone(77) || !b.gone(77) || b.gone(78) || b.gate == nil || !*b.gate {
		t.Fatal("the gate's cgroup-gone proof or start gate rules are not wired")
	}
	g := s.gate.Load()
	if _, err := g.JoinAndMark(t.Context(), testSandbox("sb1"), selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce)), soon()); err != nil {
		t.Fatal(err)
	}
	other := gateSandbox{UID: "kept", SandboxID: "sb2", CgroupID: 78}
	if _, err := g.JoinAndMark(t.Context(), other, selected(sandboxpolicy.Seq{Config: 1, Input: 1}, gatePolicy("p1", api.ModeEnforce)), soon()); err != nil {
		t.Fatal(err)
	}
	if err := g.ReleaseSandbox(t.Context(), gateSandbox{UID: "gone-too", SandboxID: "sb3", CgroupID: 77}, soon()); err != nil {
		t.Fatal(err)
	}
	g.prune() // the second ESTALE for 77 (the first came above)
	g.podMu.Lock()
	_, goneKept := g.pods["pod-uid"]
	_, liveKept := g.pods["kept"]
	_, tombKept := g.tombstones["sb3"]
	g.podMu.Unlock()
	if goneKept || !liveKept || tombKept {
		t.Fatalf("prune: gone entry kept %v, live entry kept %v, gone tombstone kept %v", goneKept, liveKept, tombKept)
	}
	g.wait()
}
