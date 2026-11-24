package integration

// Regression tests for the S5 review v4 findings, ported from the
// reviewer's probes P1 to P3: an ErrPolicyEntry section advances the
// reclassification memo (V4-1), and a mark or unmark that keeps failing
// backs off (V4-2). From the S5b review v1 probes P1 and P3: an Unknown
// classification never backs off, so a pod recovers on the first refresh
// after an API outage (B1); plus the new-mark reset (B4) and the 60 s cap
// (B5).

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// v4AuditMarkedThenEnforce marks an NRI pod under an Audit policy, then
// turns the policy to enforce and sets the refresh sequence to the new
// classification's.
func v4AuditMarkedThenEnforce(t *testing.T) (*Service, *nriTestBackend, *nriGate, sandboxpolicy.Seq) {
	t.Helper()
	s, backend := nriTestService(t)
	useAuditPolicy(t, s, backend)
	n := readyNRIGate(t, s, backend)
	s.nriGate = n
	req := sandboxpolicy.ClassifyRequest{Pod: sandboxpolicy.NRIPod{UID: "pod-uid", Namespace: "ns", Name: "pod"}}
	c := n.Classify(t.Context(), req)
	sb, err := n.Sandbox(nriTestPod("sb1", 42))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.JoinAndMark(t.Context(), sb, c, soon()); err != nil {
		t.Fatal(err)
	}
	fresh, _ := nriTestService(t)
	s.Controller = fresh.Controller
	s.inputEpoch.Add(1)
	c2 := n.Classify(t.Context(), req)
	if !c2.Strict || c2.Seq == c.Seq {
		t.Fatalf("strict classification %+v", c2)
	}
	s.podSeq = &c2.Seq
	return s, backend, n, c2.Seq
}

// v4Clock replaces the gate's backoff clock with one the test steps.
func v4Clock(n *nriGate) *time.Time {
	clock := time.Unix(1_000_000, 0)
	n.now = func() time.Time { return clock }
	return &clock
}

func v4Payload(n *nriGate) nriPayload {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.payloads["pod-uid"]
}

// TestReviewV4PolicyEntryAdvancesMemo (V4-1, probe P1): a section that
// answers ErrPolicyEntry (an adopted entry at least as strict as the plan)
// is not a failure. The memo advances, so 4 refreshes at one sequence mark
// once, and the pod keeps its mark.
func TestReviewV4PolicyEntryAdvancesMemo(t *testing.T) {
	s, backend, n, seq := v4AuditMarkedThenEnforce(t)
	backend.mu.Lock()
	backend.markErr = fmt.Errorf("privilege pod ns/pod: %w", sandboxpolicy.ErrPolicyEntry)
	backend.mu.Unlock()
	before := backend.count("MarkPod")
	for range 4 {
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	p := v4Payload(n)
	t.Logf("MarkPod %d -> %d, memo %v, refresh seq %v, mark held %v", before, backend.count("MarkPod"), p.seq, seq, n.HoldsMark("pod-uid"))
	if backend.count("MarkPod") != before+1 || p.seq != seq || p.fails != 0 {
		t.Fatalf("ErrPolicyEntry did not advance the memo: MarkPod %d -> %d, payload %+v", before, backend.count("MarkPod"), p)
	}
	if !n.HoldsMark("pod-uid") {
		t.Fatal("the pod lost its mark")
	}
}

// TestReviewV4SectionFailureBacksOff (V4-2, probe P2): a section that fails
// for good is retried, and reported, at most on the backoff schedule (the
// next refresh, then 5 s doubling to 60 s), never on every refresh. The
// mark and the memo stay. A new sequence retries at once, and a recovery
// clears the backoff.
func TestReviewV4SectionFailureBacksOff(t *testing.T) {
	s, backend, n, seq := v4AuditMarkedThenEnforce(t)
	clock := v4Clock(n)
	var reports atomic.Int32
	s.options.OnError = func(error) { reports.Add(1) }
	backend.mu.Lock()
	backend.markErr = errors.New("privilege: instance not ready")
	backend.mu.Unlock()

	// No time passes: the first failure and its one immediate retry.
	before := backend.count("MarkPod")
	for range 10 {
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	if got := backend.count("MarkPod") - before; got != 2 || reports.Load() != 2 {
		t.Fatalf("10 refreshes with no time passing: %d MarkPod, %d reports; want 2, 2", got, reports.Load())
	}

	// Then 30 refreshes 5 s apart (150 s), at the same sequence. The third
	// to seventh failures wait 10, 20, 40, 60 and 60 s (capped): tries at
	// +5, +15, +35, +75 and +135 s, 5 instead of 30.
	before, reports0 := backend.count("MarkPod"), reports.Load()
	for range 30 {
		*clock = clock.Add(5 * time.Second)
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	p := v4Payload(n)
	got := backend.count("MarkPod") - before
	t.Logf("30 refreshes over 150 s: MarkPod %d, reports %d, payload fails %d retryAt +%v", got, reports.Load()-reports0, p.fails, p.retryAt.Sub(*clock))
	if got != 5 || reports.Load()-reports0 != 5 {
		t.Fatalf("30 refreshes over 150 s: %d MarkPod, %d reports; want 5, 5 (bounded backoff)", got, reports.Load()-reports0)
	}
	// The 7th failure (at +135 s) waits the 60 s cap: its retry is due at
	// +195 s, 45 s after the last refresh. The next failure waits 60 s too
	// (S5b review v1 B5: the values are literal, not the constant).
	if p.fails != 7 || p.retryAt.Sub(*clock) != 45*time.Second {
		t.Fatalf("after 7 failures: fails %d, next retry in %v; want 7, 45s", p.fails, p.retryAt.Sub(*clock))
	}
	*clock = p.retryAt
	s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	if p = v4Payload(n); p.fails != 8 || p.retryAt.Sub(*clock) != 60*time.Second {
		t.Fatalf("the 8th failure: fails %d, next retry in %v; want 8, 60s (the cap)", p.fails, p.retryAt.Sub(*clock))
	}
	if p.seq == seq || !n.HoldsMark("pod-uid") {
		t.Fatalf("the backoff advanced the memo or dropped the mark: payload %+v, mark %v", p, n.HoldsMark("pod-uid"))
	}

	// A new sequence retries at once, mid-backoff.
	s.inputEpoch.Add(1)
	seq2 := n.Classify(t.Context(), sandboxpolicy.ClassifyRequest{Pod: sandboxpolicy.NRIPod{UID: "pod-uid", Namespace: "ns", Name: "pod"}}).Seq
	if seq2 == seq {
		t.Fatal("the sequence did not move")
	}
	s.podSeq = &seq2
	before = backend.count("MarkPod")
	s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	if backend.count("MarkPod") != before+1 {
		t.Fatalf("a new sequence did not retry at once: MarkPod %d -> %d", before, backend.count("MarkPod"))
	}

	// Recovery: the immediate retry succeeds, the memo advances and the
	// backoff is cleared.
	backend.mu.Lock()
	backend.markErr = nil
	backend.mu.Unlock()
	s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	p = v4Payload(n)
	if p.seq != seq2 || p.fails != 0 || !p.retryAt.IsZero() {
		t.Fatalf("a recovery did not clear the backoff: payload %+v", p)
	}
	backend.mu.Lock()
	r := backend.records["pod-uid"]
	strict := r != nil && r.strict
	backend.mu.Unlock()
	if !strict {
		t.Fatal("the pod is not Strict-marked after the recovery")
	}

	// A later failure starts the schedule again: its first retry is
	// immediate, not 60 s away.
	backend.mu.Lock()
	backend.markErr = errors.New("privilege: instance not ready")
	backend.mu.Unlock()
	s.inputEpoch.Add(1)
	seq3 := sandboxpolicy.Seq{Config: seq2.Config, Input: s.inputEpoch.Load()}
	s.podSeq = &seq3
	before = backend.count("MarkPod")
	for range 3 {
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	if backend.count("MarkPod") != before+2 {
		t.Fatalf("after a recovery, a new failure did not restart the backoff: MarkPod %d -> %d", before, backend.count("MarkPod"))
	}
}

// TestReviewV4NewMarkClearsBackoff (S5b review v1 B4): a new mark (a new
// container's JoinAndMark) mid-backoff replaces the payload and starts
// with no backoff, instead of inheriting the old one.
func TestReviewV4NewMarkClearsBackoff(t *testing.T) {
	s, backend, n, _ := v4AuditMarkedThenEnforce(t)
	v4Clock(n)
	backend.mu.Lock()
	backend.markErr = errors.New("privilege: instance not ready")
	backend.mu.Unlock()
	for range 3 {
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	if p := v4Payload(n); p.fails != 2 || p.retryAt.IsZero() {
		t.Fatalf("no backoff after 2 failures: payload %+v", p)
	}
	sb, err := n.Sandbox(nriTestPod("sb1", 42))
	if err != nil {
		t.Fatal(err)
	}
	c := n.Classify(t.Context(), sandboxpolicy.ClassifyRequest{Pod: sandboxpolicy.NRIPod{UID: "pod-uid", Namespace: "ns", Name: "pod"}})
	_, _ = n.JoinAndMark(t.Context(), sb, c, soon())
	if p := v4Payload(n); p.fails != 0 || !p.retryAt.IsZero() || p.failSeq != (sandboxpolicy.Seq{}) {
		t.Fatalf("a new mark inherited the backoff: payload %+v", p)
	}
}

// v4AuditNRIOnlyThenEnforce is the S5b review v1 probe P1 setup: an
// Audit-marked pod the informer misses (NRI-only, classified by GET) whose
// policy turns enforce. Its GETs fail while down() is true.
func v4AuditNRIOnlyThenEnforce(t *testing.T, down func() bool) (*Service, *nriTestBackend, *nriGate) {
	t.Helper()
	s, backend := nriTestService(t)
	useAuditPolicy(t, s, backend)
	n := readyNRIGate(t, s, backend)
	s.nriGate = n
	c := n.Classify(t.Context(), sandboxpolicy.ClassifyRequest{Pod: sandboxpolicy.NRIPod{UID: "pod-uid", Namespace: "ns", Name: "pod"}})
	sb, err := n.Sandbox(nriTestPod("sb1", 42))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.JoinAndMark(t.Context(), sb, c, soon()); err != nil {
		t.Fatal(err)
	}
	if strictRecordV4(backend) {
		t.Fatal("the pod is Strict-marked under the Audit policy")
	}
	idx := s.pods.Core().V1().Pods().Informer().GetIndexer()
	_ = idx.Delete(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid"}})
	s.options.Kubernetes.(*kubefake.Clientset).PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		if down() {
			return true, nil, errors.New("transient API error")
		}
		return false, nil, nil
	})
	fresh, _ := nriTestService(t)
	s.Controller = fresh.Controller // enforce
	s.inputEpoch.Add(1)
	seq := sandboxpolicy.Seq{Config: c.Seq.Config + 100, Input: s.inputEpoch.Load()}
	s.podSeq = &seq
	return s, backend, n
}

func strictRecordV4(b *nriTestBackend) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.records["pod-uid"]
	return r != nil && r.strict
}

// v4OutageRecovery refreshes every 5 s, at one sequence, until done() or
// 80 refreshes, and returns when done() first held (-1: never).
func v4OutageRecovery(s *Service, n *nriGate, clock *time.Time, start time.Time, done func() bool) time.Duration {
	for range 80 {
		s.bindGatePodPlans(context.Background(), n.gate, nil, nil, false)
		if done() {
			return clock.Sub(start)
		}
		*clock = clock.Add(5 * time.Second)
	}
	return -1
}

// TestReviewV4StrengthenOnFirstRefreshAfterOutage (S5b review v1 B1, probe
// P1): an NRI-only Audit-marked pod whose policy turned enforce during an
// API outage is Strict-marked on the first refresh after the API answers
// again, whatever the outage's length. Unknown never backs off.
func TestReviewV4StrengthenOnFirstRefreshAfterOutage(t *testing.T) {
	for _, outage := range []time.Duration{10 * time.Second, 20 * time.Second, 45 * time.Second, 85 * time.Second, 150 * time.Second} {
		start := time.Unix(1_000_000, 0)
		clock := start
		s, backend, n := v4AuditNRIOnlyThenEnforce(t, func() bool { return clock.Sub(start) < outage })
		n.now = func() time.Time { return clock }
		at := v4OutageRecovery(s, n, &clock, start, func() bool { return strictRecordV4(backend) })
		t.Logf("outage %v: Strict at +%v", outage, at)
		if at != outage {
			t.Fatalf("outage %v: Strict at +%v, want +%v (the first refresh after recovery)", outage, at, outage)
		}
	}
}

// TestReviewV4UnmarkOnFirstRefreshAfterOutage (S5b review v1 B1 and B6,
// probe P3): an NRI-only Strict-marked pod whose policy was removed during
// an API outage is unmarked on the first refresh after the API answers
// again.
func TestReviewV4UnmarkOnFirstRefreshAfterOutage(t *testing.T) {
	for _, outage := range []time.Duration{10 * time.Second, 45 * time.Second, 85 * time.Second, 150 * time.Second} {
		start := time.Unix(1_000_000, 0)
		clock := start
		s, backend := nriTestService(t)
		n := readyNRIGate(t, s, backend)
		s.nriGate = n
		n.now = func() time.Time { return clock }
		c := n.Classify(t.Context(), sandboxpolicy.ClassifyRequest{Pod: sandboxpolicy.NRIPod{UID: "pod-uid", Namespace: "ns", Name: "pod"}})
		sb, err := n.Sandbox(nriTestPod("sb1", 42))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.JoinAndMark(t.Context(), sb, c, soon()); err != nil {
			t.Fatal(err)
		}
		idx := s.pods.Core().V1().Pods().Informer().GetIndexer()
		_ = idx.Delete(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid"}})
		s.options.Kubernetes.(*kubefake.Clientset).PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			if clock.Sub(start) < outage {
				return true, nil, errors.New("transient API error")
			}
			return false, nil, nil
		})
		useNoPolicy(t, s, backend)
		s.inputEpoch.Add(1)
		seq := sandboxpolicy.Seq{Config: c.Seq.Config + 100, Input: s.inputEpoch.Load()}
		s.podSeq = &seq
		at := v4OutageRecovery(s, n, &clock, start, func() bool { return backend.count("UnmarkPod") > 0 })
		t.Logf("outage %v: unmarked at +%v", outage, at)
		if at != outage {
			t.Fatalf("outage %v: unmarked at +%v, want +%v (the first refresh after recovery)", outage, at, outage)
		}
	}
}

// TestReviewV4PermanentUnknownNoBackoff (V4-2 probe P3, inverted by the
// S5b review v1 B1 ruling): an NRI-only pod whose GET answers NotFound (a
// force-deleted pod) is Unknown for good. It is retried on every refresh,
// bounded only by reclassifyBudget, with no backoff state, and it keeps
// its mark, payload and memo.
func TestReviewV4PermanentUnknownNoBackoff(t *testing.T) {
	s, backend := nriTestService(t)
	n := readyNRIGate(t, s, backend)
	s.nriGate = n
	clock := v4Clock(n)
	req := sandboxpolicy.ClassifyRequest{Pod: sandboxpolicy.NRIPod{UID: "pod-uid", Namespace: "ns", Name: "pod"}}
	c := n.Classify(t.Context(), req)
	sb, err := n.Sandbox(nriTestPod("sb1", 42))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.JoinAndMark(t.Context(), sb, c, soon()); err != nil {
		t.Fatal(err)
	}
	idx := s.pods.Core().V1().Pods().Informer().GetIndexer()
	_ = idx.Delete(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid"}})
	var gets atomic.Int32
	s.options.Kubernetes.(*kubefake.Clientset).PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		gets.Add(1)
		return true, nil, errors.New(`pods "pod" not found`)
	})
	useNoPolicy(t, s, backend)
	s.inputEpoch.Add(1)
	seq := sandboxpolicy.Seq{Config: c.Seq.Config + 100, Input: s.inputEpoch.Load()}
	s.podSeq = &seq
	for i := range 10 {
		if i > 0 {
			*clock = clock.Add(5 * time.Second)
		}
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	p := v4Payload(n)
	t.Logf("10 refreshes over 45 s: pod GETs %d, UnmarkPod %d, payload %+v", gets.Load(), backend.count("UnmarkPod"), p)
	if gets.Load() != 10 {
		t.Fatalf("10 refreshes: %d pod GETs, want 10 (Unknown never backs off)", gets.Load())
	}
	if p.fails != 0 || !p.retryAt.IsZero() || p.failSeq != (sandboxpolicy.Seq{}) {
		t.Fatalf("an Unknown pod has backoff state: payload %+v", p)
	}
	if backend.count("UnmarkPod") != 0 || p.sb.ID != sb.ID || p.seq == seq || !n.HoldsMark("pod-uid") {
		t.Fatalf("an Unknown pod lost its mark, payload or memo: UnmarkPod %d, payload %+v", backend.count("UnmarkPod"), p)
	}
}
