package integration

import (
	"errors"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/startgate"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// useAuditPolicy replaces the test service's controller with one whose only
// policy ("priv", every pod of ns) is in audit mode.
func useAuditPolicy(t *testing.T, s *Service, backend sandboxpolicy.Backend) {
	t.Helper()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{sandboxpolicy.PolicyGVR: "SandboxPolicyList", sandboxpolicy.ClusterPolicyGVR: "ClusterSandboxPolicyList", sandboxpolicy.ClassesGVR: "SandboxPolicyClassesList"})
	p := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.SchemeGroupVersion.String(), "kind": "SandboxPolicy", "metadata": map[string]any{"name": "priv", "namespace": "ns", "uid": "policy-uid", "generation": int64(1)}, "spec": map[string]any{"selector": map[string]any{"podSelector": map[string]any{}}, "mode": "audit", "containers": []any{"*"}, "privilege": map[string]any{"default": "allow", "rules": []any{map[string]any{"name": "no-chroot", "action": "deny", "target": map[string]any{"syscall": []any{"chroot"}}}}}}}}
	if _, err := client.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Create(t.Context(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	c, err := sandboxpolicy.NewController(client, backend, nil, nil, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.Controller = c
}

// readyNRIGate is an enabled nriGate over the test service: synced
// informers, a resolver that knows only pause PID 42, and PIDs 42 and 43
// alive.
func readyNRIGate(t *testing.T, s *Service, backend *nriTestBackend) *nriGate {
	t.Helper()
	n := s.newNRIGate(backend, "/proc")
	if err := s.enableStartGate(t.Context(), startGateSyscalls()); err != nil {
		t.Fatal(err)
	}
	n.gate = s.gate.Load()
	n.resolve = func(pod podSandbox) (string, uint64, error) {
		if pod.PausePID != 42 {
			return "", 0, errors.New("pause process: no PID")
		}
		return nriTestPodPath, 77, nil
	}
	n.alive = func(pid uint32) bool { return pid == 42 || pid == 43 }
	n.restartSurvival = func() bool { return true }
	s.pods.Start(t.Context().Done())
	s.pods.WaitForCacheSync(t.Context().Done())
	return n
}

// TestS5ReviewF1DeadSandboxThroughNRIGate (S5 review v1 F1, owner ruling
// batch 6): through the real nriGate and podGate, the NotReady sandbox of a
// completed Selected pod (Strict and Audit) has no live pause process and
// cannot be marked, but it joins as Unselected and still counts for the
// pod's last sandbox: removing the live sandbox does not release the pod.
func TestS5ReviewF1DeadSandboxThroughNRIGate(t *testing.T) {
	for _, audit := range []bool{false, true} {
		s, backend := nriTestService(t)
		if audit {
			useAuditPolicy(t, s, backend.fakeGateBackend)
		}
		n := readyNRIGate(t, s, backend)
		c := n.Classify(t.Context(), sandboxpolicy.ClassifyRequest{Pod: sandboxpolicy.NRIPod{UID: "pod-uid", Namespace: "ns", Name: "pod"}})
		if c.Class != sandboxpolicy.PodSelected || c.Strict == audit {
			t.Fatalf("audit=%v: classification %+v", audit, c)
		}
		if n.PauseAlive(nriTestPod("sb-done", 0)) || n.PauseAlive(nriTestPod("sb-done", 77)) || !n.PauseAlive(nriTestPod("sb1", 42)) {
			t.Fatal("PauseAlive")
		}
		dead, err := n.Sandbox(nriTestPod("sb-done", 0))
		if err == nil {
			t.Fatal("the dead sandbox resolved")
		}
		if _, err := n.JoinAndMark(t.Context(), dead, c, soon()); !errors.Is(err, errNoCgroup) {
			t.Fatalf("audit=%v: a dead sandbox is unmarkable: %v", audit, err)
		}
		live, err := n.Sandbox(nriTestPod("sb1", 42))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.JoinAndMark(t.Context(), live, c, soon()); err != nil {
			t.Fatal(err)
		}
		if err := n.JoinUnselected(dead); err != nil {
			t.Fatal(err)
		}
		if err := n.ReleaseSandbox(t.Context(), live, soon()); err != nil || backend.count("ReleasePod") != 0 {
			t.Fatalf("audit=%v: the dead sandbox did not keep the pod: %v, calls %v", audit, err, backend.calls)
		}
		if err := n.ReleaseSandbox(t.Context(), dead, soon()); err != nil || backend.count("ReleasePod") != 1 {
			t.Fatalf("audit=%v: the last sandbox's removal did not release: %v, calls %v", audit, err, backend.calls)
		}
		// S5 review v1 F5: a tombstoned sandbox answers ErrSandboxRemoved.
		if err := n.JoinUnselected(dead); !errors.Is(err, startgate.ErrSandboxRemoved) {
			t.Fatalf("tombstoned JoinUnselected = %v", err)
		}
	}
}

// useNoPolicy replaces the controller with one that has no policy: every
// pod is Unselected (the Strict policy was deleted). Ported from the S5
// review v2 reproduction.
func useNoPolicy(t *testing.T, s *Service, backend sandboxpolicy.Backend) {
	t.Helper()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{sandboxpolicy.PolicyGVR: "SandboxPolicyList", sandboxpolicy.ClusterPolicyGVR: "ClusterSandboxPolicyList", sandboxpolicy.ClassesGVR: "SandboxPolicyClassesList"})
	c, err := sandboxpolicy.NewController(client, backend, nil, nil, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.Controller = c
}

// TestReviewV2F6ListedUnselectedPodNeverUnmarked (S5 review v2 N1, ported
// as a regression test): an NRI-marked Strict pod that the API lists
// becomes Unselected (its policy is deleted). The API path gives it no
// plan, so it is not in the bind's pods, and BindPodsAt keeps a start gate
// record it does not list. The refresh's reclassification must unmark it.
// The test replaces the controller, which restarts configSeq, so it moves
// the input epoch as a policy event does in production.
func TestReviewV2F6ListedUnselectedPodNeverUnmarked(t *testing.T) {
	s, backend := nriTestService(t)
	n := readyNRIGate(t, s, backend)
	s.nriGate = n
	c := n.Classify(t.Context(), sandboxpolicy.ClassifyRequest{Pod: sandboxpolicy.NRIPod{UID: "pod-uid", Namespace: "ns", Name: "pod"}})
	if c.Class != sandboxpolicy.PodSelected || !c.Strict {
		t.Fatalf("classification %+v", c)
	}
	sb, err := n.Sandbox(nriTestPod("sb1", 42))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.JoinAndMark(t.Context(), sb, c, soon()); err != nil {
		t.Fatal(err)
	}
	useNoPolicy(t, s, backend)
	s.inputEpoch.Add(1)
	c2 := n.Classify(t.Context(), sandboxpolicy.ClassifyRequest{Pod: sandboxpolicy.NRIPod{UID: "pod-uid", Namespace: "ns", Name: "pod"}})
	if c2.Class != sandboxpolicy.PodUnselected || c2.Seq == c.Seq {
		t.Fatalf("after deleting the policy: %+v", c2)
	}
	s.podSeq = &c2.Seq
	// The API lists the pod (scheduled), with no plan: pods is empty.
	for range 3 {
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	backend.mu.Lock()
	_, kept := backend.records["pod-uid"]
	backend.mu.Unlock()
	if backend.count("UnmarkPod") != 1 || kept {
		t.Fatalf("a listed Unselected pod was not unmarked: calls %v, record kept %v", backend.calls, kept)
	}
	n.mu.Lock()
	left := len(n.payloads)
	n.mu.Unlock()
	if left != 0 {
		t.Fatal("an unmarked pod is still reclassified")
	}
}

// TestS5ReviewV2N1BoundPodNotReclassified: a marked pod the refresh binds
// with a plan is the refresh's (not reclassified); the same pod, unbound,
// is reclassified once per sequence change (the refresh stays bounded, S5
// review v1 F6).
func TestS5ReviewV2N1BoundPodNotReclassified(t *testing.T) {
	s, backend := nriTestService(t)
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
	marks := backend.count("MarkPod")
	moved := sandboxpolicy.Seq{Config: c.Seq.Config, Input: c.Seq.Input + 1}
	s.podSeq = &moved
	bound := []sandboxpolicy.PodBinding{{PodUID: "pod-uid", Namespace: "ns", PodName: "pod", CgroupID: 77, CgroupPath: nriTestPodPath, Plan: c.Sections[sandboxpolicy.SectionPrivilege].Plan}}
	s.bindGatePodPlans(t.Context(), n.gate, bound, nil, false)
	if backend.count("MarkPod") != marks {
		t.Fatalf("a bound pod was reclassified: %v", backend.calls)
	}
	for range 3 {
		s.bindGatePodPlans(t.Context(), n.gate, nil, nil, false)
	}
	if backend.count("MarkPod") != marks+1 {
		t.Fatalf("an unbound pod was not reclassified exactly once at the new sequence: %v", backend.calls)
	}
	// The poll never reclassifies.
	again := sandboxpolicy.Seq{Config: c.Seq.Config, Input: c.Seq.Input + 2}
	s.podSeq = &again
	s.bindGatePodPlans(t.Context(), n.gate, nil, nil, true)
	if backend.count("MarkPod") != marks+1 {
		t.Fatalf("the poll reclassified: %v", backend.calls)
	}
}

// TestS5ReviewV2N5OverflowNoticeOnEveryPolicy (S5 review v2 N5): once the
// plugin evicted status entries, every policy's report carries the
// overflow notice, even one with no listed pod left; with no eviction and
// no pod, the report passes unchanged.
func TestS5ReviewV2N5OverflowNoticeOnEveryPolicy(t *testing.T) {
	inner := &captureStatus{}
	var evicted uint64
	w := startGateStatusWriter{inner: inner, states: func() []startgate.PodStatus { return nil }, evicted: func() uint64 { return evicted }}
	report := func() *api.SandboxPolicyNodeStatus {
		return &api.SandboxPolicyNodeStatus{Spec: api.SandboxPolicyNodeStatusSpec{PolicyRef: api.SandboxPolicyReference{UID: "p1"}}, Status: &api.NodeStatus{}}
	}
	in := report()
	if err := w.WriteStatus(t.Context(), in); err != nil || inner.got[0] != in {
		t.Fatalf("no eviction: the report changed (%v)", err)
	}
	evicted = 3
	if err := w.WriteStatus(t.Context(), report()); err != nil {
		t.Fatal(err)
	}
	conds := inner.got[1].Status.Conditions
	if len(conds) != 1 || conds[0].Type != "StartGatePods" || conds[0].Status != metav1.ConditionFalse || !strings.Contains(conds[0].Message, "3 older entries evicted") {
		t.Fatalf("conditions %+v", conds)
	}
}
