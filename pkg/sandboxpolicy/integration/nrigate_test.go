package integration

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/startgate"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
)

// nriTestBackend is the pod gate's fake backend with the NRI sync state.
type nriTestBackend struct {
	*fakeGateBackend
	syncMu       sync.Mutex
	synced       []string
	disconnected []uint64
}

func (b *nriTestBackend) SetNRISynced(epoch uint64, proven map[uint64]bool) {
	b.syncMu.Lock()
	defer b.syncMu.Unlock()
	b.synced = append(b.synced, fmt.Sprintf("%d:%d", epoch, len(proven)))
}

func (b *nriTestBackend) SetNRIDisconnected(epoch uint64) {
	b.syncMu.Lock()
	defer b.syncMu.Unlock()
	b.disconnected = append(b.disconnected, epoch)
}

// nriTestService is gateTestService with pod and namespace informers over
// its fake clientset.
func nriTestService(t *testing.T) (*Service, *nriTestBackend) {
	t.Helper()
	backend := &nriTestBackend{fakeGateBackend: newFakeGateBackend()}
	s := gateTestService(t, backend.fakeGateBackend)
	s.backend = backend
	s.pods = informers.NewSharedInformerFactory(s.options.Kubernetes, 0)
	s.namespaces = s.pods
	return s, backend
}

const nriTestPodPath = "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice"

func nriTestPod(id string, pid uint32) *nriapi.PodSandbox {
	return &nriapi.PodSandbox{Id: id, Uid: "pod-uid", Namespace: "ns", Name: "pod", Pid: pid, Linux: &nriapi.LinuxPodSandbox{CgroupParent: "kubepods-besteffort-podpod_uid.slice"}}
}

// TestS5NRIGateThroughPodGate: the adapter between the plugin and the pod
// gate: the classification reads the informers and the snapshot, a joined
// sandbox keeps its join's cgroup, Unmark writes only a mark the gate holds,
// the hold confirms through the backend, the reclassification of a pod the
// API path did not list marks it at the new classification, and the release
// drops the pod.
func TestS5NRIGateThroughPodGate(t *testing.T) {
	s, backend := nriTestService(t)
	n := s.newNRIGate(backend, "/proc")
	if err := n.Registration(); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("Registration before the gate = %v", err)
	}
	if err := s.enableStartGate(t.Context(), startGateSyscalls()); err != nil {
		t.Fatal(err)
	}
	n.gate = s.gate.Load()
	n.resolve = func(pod podSandbox) (string, uint64, error) {
		if pod.PausePID != 42 {
			return "", 0, errors.New("no pause process")
		}
		return nriTestPodPath, 77, nil
	}
	s.pods.Start(t.Context().Done())
	s.pods.WaitForCacheSync(t.Context().Done())
	// The registration gate: restart survival needs a BPF filesystem here,
	// and the PID namespace check refuses another procfs.
	if err := n.Registration(); RestartPinRoot() == "" && (err == nil || !strings.Contains(err.Error(), "restart survival")) || RestartPinRoot() != "" && err != nil {
		t.Fatalf("Registration = %v (restart pin root %q)", err, RestartPinRoot())
	}
	n.procRoot = t.TempDir()
	if err := n.Registration(); err == nil {
		t.Fatal("Registration passed with a procfs of another PID namespace")
	}
	n.procRoot = "/proc"

	ctx := t.Context()
	c := n.Classify(ctx, sandboxpolicy.ClassifyRequest{Pod: sandboxpolicy.NRIPod{UID: "pod-uid", Namespace: "ns", Name: "pod"}})
	if c.Class != sandboxpolicy.PodSelected || !c.Strict || len(c.Sections) != 1 || len(c.Policies) != 1 || c.Policies[0].UID != "policy-uid" {
		t.Fatalf("classification %+v", c)
	}
	if _, err := n.Sandbox(nriTestPod("sb1", 0)); err == nil {
		t.Fatal("an unjoined sandbox without a pause process resolved")
	}
	sb, err := n.Sandbox(nriTestPod("sb1", 42))
	if err != nil || sb.CgroupID != 77 || sb.CgroupPath != nriTestPodPath {
		t.Fatalf("Sandbox = %+v, %v", sb, err)
	}
	if err := n.Unmark(ctx, sb, c.Seq, soon()); err != nil || backend.count("UnmarkPod") != 0 {
		t.Fatalf("Unmark without a mark: %v, calls %v", err, backend.calls)
	}
	res, err := n.JoinAndMark(ctx, sb, c, soon())
	if err != nil || len(res) != 1 || res[0].Err != nil || backend.count("MarkPod") != 1 {
		t.Fatalf("JoinAndMark = %v, %v; calls %v", res, err, backend.calls)
	}
	// A joined sandbox keeps its join's cgroup (RemovePodSandbox: the pause
	// process is gone).
	if again, err := n.Sandbox(nriTestPod("sb1", 0)); err != nil || again.CgroupID != 77 {
		t.Fatalf("joined Sandbox = %+v, %v", again, err)
	}
	confs, err := n.HoldUntilConfirmed(ctx, sb, c, soon())
	if err != nil || len(confs) != 1 || confs[0].State != sandboxpolicy.PodSectionConfirmed {
		t.Fatalf("hold = %v, %v", confs, err)
	}
	// LOW 7: a pod the refresh binds with a plan is the refresh's; an
	// unbound one is reclassified when the sequence moved, once per move.
	moved := sandboxpolicy.Seq{Config: c.Seq.Config, Input: c.Seq.Input + 1}
	n.reclassifyUnbound(ctx, map[types.UID]bool{"pod-uid": true}, moved)
	if backend.count("MarkPod") != 1 {
		t.Fatalf("a bound pod was reclassified: %v", backend.calls)
	}
	n.reclassifyUnbound(ctx, map[types.UID]bool{}, c.Seq)
	if backend.count("MarkPod") != 1 {
		t.Fatalf("a pod was reclassified at its own sequence: %v", backend.calls)
	}
	n.reclassifyUnbound(ctx, map[types.UID]bool{}, moved)
	n.reclassifyUnbound(ctx, map[types.UID]bool{}, moved)
	if backend.count("MarkPod") != 2 {
		t.Fatalf("an unbound pod was not reclassified exactly once at the new sequence: %v", backend.calls)
	}
	newer := sandboxpolicy.Seq{Config: c.Seq.Config, Input: c.Seq.Input + 1}
	if err := n.Unmark(ctx, sb, newer, soon()); err != nil || backend.count("UnmarkPod") != 1 {
		t.Fatalf("Unmark of a marked pod: %v, calls %v", err, backend.calls)
	}
	if err := n.ReleaseSandbox(ctx, sb, soon()); err != nil || backend.count("ReleasePod") != 1 {
		t.Fatalf("release: %v, calls %v", err, backend.calls)
	}
	n.mu.Lock()
	left := len(n.payloads)
	n.mu.Unlock()
	if left != 0 {
		t.Fatalf("a released pod is still reclassified (%d payloads)", left)
	}
	n.SetNRISynced(3, map[uint64]bool{9: true})
	n.SetNRIDisconnected(3)
	if !slices.Equal(backend.synced, []string{"3:1"}) || !slices.Equal(backend.disconnected, []uint64{3}) {
		t.Fatalf("sync state %v %v", backend.synced, backend.disconnected)
	}
}

type captureStatus struct {
	got []*api.SandboxPolicyNodeStatus
}

func (c *captureStatus) WriteStatus(_ context.Context, r *api.SandboxPolicyNodeStatus) error {
	c.got = append(c.got, r)
	return nil
}

// TestS5StatusWriter: the start-gate state of the pods a policy selects is
// one condition on that policy's node status, never True; with the gate off
// (or no pod of the policy) the report passes unchanged.
func TestS5StatusWriter(t *testing.T) {
	report := func(uid types.UID) *api.SandboxPolicyNodeStatus {
		return &api.SandboxPolicyNodeStatus{Spec: api.SandboxPolicyNodeStatusSpec{PolicyRef: api.SandboxPolicyReference{Kind: "SandboxPolicy", Name: string(uid), UID: uid}},
			Status: &api.NodeStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}}}
	}
	inner := &captureStatus{}
	off := startGateStatusWriter{inner: inner, states: (&Service{}).startGateStatus}
	in := report("p1")
	if err := off.WriteStatus(t.Context(), in); err != nil || len(inner.got) != 1 || inner.got[0] != in {
		t.Fatalf("gate off: the report changed (%v)", err)
	}
	states := []startgate.PodStatus{
		{UID: "a", Namespace: "ns", Name: "a", State: startgate.StatePending, Reason: "r", Policies: []types.UID{"p1"}},
		{UID: "b", Namespace: "ns", Name: "b", State: startgate.StateAuditDegraded, Reason: "r", Policies: []types.UID{"p1", "p2"}},
		{UID: "c", Namespace: "ns", Name: "c", State: startgate.StateFaulted, Reason: "r", Policies: []types.UID{"p2"}},
	}
	on := startGateStatusWriter{inner: inner, states: func() []startgate.PodStatus { return states }}
	in = report("p1")
	if err := on.WriteStatus(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	got := inner.got[len(inner.got)-1]
	if got == in || len(in.Status.Conditions) != 1 {
		t.Fatal("the writer changed its input instead of a copy")
	}
	conds := got.Status.Conditions
	if len(conds) != 2 || conds[1].Type != "StartGatePods" || conds[1].Status != metav1.ConditionFalse ||
		!strings.Contains(conds[1].Message, "ns/a: Pending") || !strings.Contains(conds[1].Message, "ns/b: AuditDegraded") || strings.Contains(conds[1].Message, "ns/c") {
		t.Fatalf("conditions %+v", conds)
	}
	in = report("p3")
	if err := on.WriteStatus(t.Context(), in); err != nil || inner.got[len(inner.got)-1] != in {
		t.Fatalf("a policy with no start-gate pod got a changed report (%v)", err)
	}
	many := make([]startgate.PodStatus, startGateStatusLimit+5)
	for i := range many {
		many[i] = startgate.PodStatus{Namespace: "ns", Name: fmt.Sprint(i), State: startgate.StatePending, Policies: []types.UID{"p1"}}
	}
	states = many
	if err := on.WriteStatus(t.Context(), report("p1")); err != nil {
		t.Fatal(err)
	}
	if msg := inner.got[len(inner.got)-1].Status.Conditions[1].Message; !strings.Contains(msg, "and 5 more") {
		t.Fatalf("unbounded message %q", msg)
	}
}
