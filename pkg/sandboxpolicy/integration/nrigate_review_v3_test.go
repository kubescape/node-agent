package integration

// Regression tests for the S5 review v3 findings, ported from the
// reviewer's probes: the reclassification memo advances only on a
// definitive outcome (V3-1, V3-2).

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestReviewV3SectionFailureMemoized (V3-2): an Audit-marked NRI pod whose
// policy turns to enforce; the reclassification's MarkPod fails in a
// section (an error inside the results, err nil). The memo does not
// advance, so the next refresh marks it again, and the pod ends Strict.
func TestReviewV3SectionFailureMemoized(t *testing.T) {
	s, backend := nriTestService(t)
	useAuditPolicy(t, s, backend)
	n := readyNRIGate(t, s, backend)
	s.nriGate = n
	req := sandboxpolicy.ClassifyRequest{Pod: sandboxpolicy.NRIPod{UID: "pod-uid", Namespace: "ns", Name: "pod"}}
	c := n.Classify(t.Context(), req)
	if c.Class != sandboxpolicy.PodSelected || c.Strict {
		t.Fatalf("audit classification %+v", c)
	}
	sb, err := n.Sandbox(nriTestPod("sb1", 42))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.JoinAndMark(t.Context(), sb, c, soon()); err != nil {
		t.Fatal(err)
	}
	// Back to the enforce policy (the default test service's).
	fresh, _ := nriTestService(t)
	s.Controller = fresh.Controller
	s.inputEpoch.Add(1)
	c2 := n.Classify(t.Context(), req)
	if !c2.Strict || c2.Seq == c.Seq {
		t.Fatalf("strict classification %+v", c2)
	}
	s.podSeq = &c2.Seq
	backend.mu.Lock()
	backend.markErr = errors.New("section not ready")
	backend.mu.Unlock()
	s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	backend.mu.Lock()
	backend.markErr = nil
	backend.mu.Unlock()
	marks := backend.count("MarkPod")
	for range 3 {
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	backend.mu.Lock()
	r := backend.records["pod-uid"]
	strict := r != nil && r.strict
	backend.mu.Unlock()
	n.mu.Lock()
	memo := n.payloads["pod-uid"].seq
	n.mu.Unlock()
	t.Logf("MarkPod after failure: %d -> %d; record strict=%v; payload memo=%v refresh seq=%v; calls=%v", marks, backend.count("MarkPod"), strict, memo, c2.Seq, backend.callNames())
	if !strict {
		t.Fatalf("the pod stayed Audit-marked while its policy is enforce")
	}
	if backend.count("MarkPod") != marks+1 || memo != c2.Seq {
		t.Fatalf("a section failure was memoized: MarkPod %d -> %d, memo %v", marks, backend.count("MarkPod"), memo)
	}
}

// TestReviewV3TransientUnknownMemoized (V3-1), from review v3 probe B: an NRI-only pod (informer miss) whose policy is
// deleted. The first reclassification's GET fails transiently -> Unknown ->
// no write, err nil -> memo set to the refresh seq. Later refreshes at the
// same seq must reclassify it again and unmark it.
func TestReviewV3TransientUnknownMemoized(t *testing.T) {
	s, backend := nriTestService(t)
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
	// The node's informer misses the pod (NRI-only).
	idx := s.pods.Core().V1().Pods().Informer().GetIndexer()
	_ = idx.Delete(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid"}})
	var fail atomic.Int32
	fail.Store(1)
	s.options.Kubernetes.(*kubefake.Clientset).PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		if fail.Add(-1) >= 0 {
			return true, nil, errors.New("transient API error")
		}
		return false, nil, nil
	})
	useNoPolicy(t, s, backend)
	s.inputEpoch.Add(1)
	seq := sandboxpolicy.Seq{Config: c.Seq.Config + 100, Input: s.inputEpoch.Load()}
	s.podSeq = &seq
	for range 4 {
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	backend.mu.Lock()
	_, kept := backend.records["pod-uid"]
	backend.mu.Unlock()
	t.Logf("UnmarkPod calls %d, record kept %v, calls %v", backend.count("UnmarkPod"), kept, backend.callNames())
	if backend.count("UnmarkPod") == 0 || kept {
		t.Fatalf("a transiently Unknown pod was memoized: never unmarked at this seq")
	}
}

// TestReviewV3ControlNoFailure: probe B without the injected failure.
func TestReviewV3ControlNoFailure(t *testing.T) {
	s, backend := nriTestService(t)
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
	// The node's informer misses the pod (NRI-only).
	idx := s.pods.Core().V1().Pods().Informer().GetIndexer()
	_ = idx.Delete(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid"}})
	var fail atomic.Int32
	fail.Store(0)
	s.options.Kubernetes.(*kubefake.Clientset).PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		if fail.Add(-1) >= 0 {
			return true, nil, errors.New("transient API error")
		}
		return false, nil, nil
	})
	useNoPolicy(t, s, backend)
	s.inputEpoch.Add(1)
	seq := sandboxpolicy.Seq{Config: c.Seq.Config + 100, Input: s.inputEpoch.Load()}
	s.podSeq = &seq
	for range 4 {
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	backend.mu.Lock()
	_, kept := backend.records["pod-uid"]
	backend.mu.Unlock()
	t.Logf("UnmarkPod calls %d, record kept %v, calls %v", backend.count("UnmarkPod"), kept, backend.callNames())
	if backend.count("UnmarkPod") == 0 || kept {
		t.Fatalf("a transiently Unknown pod was memoized: never unmarked at this seq")
	}
}

// TestReviewV3TransientUnknownKeepsAudit (V3-1), from review v3 probe C: the reverse direction of probe B. An NRI-only pod
// marked Audit; its policy turns to enforce. The first reclassification's
// GET fails transiently -> Unknown. The memo must not advance, so a later
// refresh at the same seq marks it Strict.
func TestReviewV3TransientUnknownKeepsAudit(t *testing.T) {
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
	idx := s.pods.Core().V1().Pods().Informer().GetIndexer()
	_ = idx.Delete(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid"}})
	var fail atomic.Int32
	fail.Store(1)
	s.options.Kubernetes.(*kubefake.Clientset).PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		if fail.Add(-1) >= 0 {
			return true, nil, errors.New("transient API error")
		}
		return false, nil, nil
	})
	fresh, _ := nriTestService(t)
	s.Controller = fresh.Controller // enforce
	s.inputEpoch.Add(1)
	seq := sandboxpolicy.Seq{Config: c.Seq.Config + 100, Input: s.inputEpoch.Load()}
	s.podSeq = &seq
	for range 4 {
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	backend.mu.Lock()
	r := backend.records["pod-uid"]
	strict := r != nil && r.strict
	backend.mu.Unlock()
	t.Logf("record strict=%v, MarkPod calls %d, calls %v", strict, backend.count("MarkPod"), backend.callNames())
	if !strict {
		t.Fatalf("enforce policy, but the NRI-only pod stays Audit-marked at this seq after one transient GET failure")
	}
}
