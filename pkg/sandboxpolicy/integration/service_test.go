package integration

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type serviceTestBackend struct {
	replaces, withdraws, closes, settles int
	closeErr                             error
	onReplace, onClose                   func()
}

func (b *serviceTestBackend) Replace(_ context.Context, _ sandboxpolicy.Binding, p sandboxpolicy.Plan) (sandboxpolicy.ReplaceResult, error) {
	b.replaces++
	if b.onReplace != nil {
		b.onReplace()
	}
	return sandboxpolicy.ReplaceResult{Committed: true, ActiveRevision: p.Revision}, nil
}
func (b *serviceTestBackend) Withdraw(context.Context, sandboxpolicy.Binding) (sandboxpolicy.WithdrawResult, error) {
	b.withdraws++
	return sandboxpolicy.WithdrawResult{Committed: true}, nil
}
func (b *serviceTestBackend) Close(context.Context) error {
	b.closes++
	if b.onClose != nil {
		b.onClose()
	}
	return b.closeErr
}
func (b *serviceTestBackend) Settle(context.Context) error { b.settles++; return nil }
func testService(t *testing.T) (*Service, *serviceTestBackend) {
	t.Helper()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{sandboxpolicy.PolicyGVR: "SandboxPolicyList", sandboxpolicy.ClusterPolicyGVR: "ClusterSandboxPolicyList", sandboxpolicy.ClassesGVR: "SandboxPolicyClassesList"})
	p := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.SchemeGroupVersion.String(), "kind": "SandboxPolicy", "metadata": map[string]any{"name": "test", "namespace": "ns", "uid": "policy-uid", "generation": int64(1)}, "spec": map[string]any{"selector": map[string]any{"podSelector": map[string]any{}}, "mode": "enforce", "containers": []any{"app"}, "exec": map[string]any{"default": "deny"}}}}
	if _, err := client.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Create(t.Context(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	backend := &serviceTestBackend{}
	controller, err := sandboxpolicy.NewController(client, backend, nil, nil, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	exporter, err := sandboxpolicy.NewVerdictExporter(sandboxpolicy.ExporterOptions{Capacity: 8})
	if err != nil {
		t.Fatal(err)
	}
	sections, err := sandboxpolicy.NewSectionExporter(sandboxpolicy.SectionExporterOptions{Capacity: 8})
	if err != nil {
		t.Fatal(err)
	}
	return &Service{Controller: controller, backend: backend, exporter: exporter, sectionExporter: sections, closeRuntime: func() error { return nil }, options: ServiceOptions{Dynamic: client}, bindings: map[string]sandboxpolicy.Binding{}, done: make(chan struct{}), wake: make(chan struct{}, 1)}, backend
}
func serviceBinding() sandboxpolicy.Binding {
	return sandboxpolicy.Binding{Runtime: "containerd", ContainerID: "exact-id", CgroupID: 42, CgroupPath: "/pod/container", PID: 10, MountNamespace: 99, PodUID: "pod-uid", PodName: "pod", Namespace: "ns", ContainerName: "app", Kind: "regular", PodLabels: map[string]string{"app": "test"}}
}
func TestServiceSnapshotFailureNeverWithdraws(t *testing.T) {
	s, b := testService(t)
	binding := serviceBinding()
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) { return []sandboxpolicy.Binding{binding}, nil }
	s.refresh(t.Context())
	if b.replaces != 1 {
		t.Fatalf("initial bind: %d", b.replaces)
	}
	failure := errors.New("API unavailable")
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) { return nil, failure }
	s.refresh(t.Context())
	if b.withdraws != 0 || s.Controller.LastError() == nil {
		t.Fatal("failed snapshot withdrew or hid readiness failure")
	}
	v := sandboxpolicy.Verdict{ContainerID: binding.ContainerID, CgroupID: binding.CgroupID, PodUID: binding.PodUID, BindingPID: binding.PID, MountNamespace: binding.MountNamespace}
	if _, ok := s.resolveBinding(v); !ok {
		t.Fatal("last binding metadata removed")
	}
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) { return nil, nil }
	s.refresh(t.Context())
	if b.withdraws != 1 {
		t.Fatalf("valid empty snapshot did not withdraw: %d", b.withdraws)
	}
	if _, ok := s.resolveBinding(v); ok {
		t.Fatal("deleted identity still resolves")
	}
}
func TestServiceMetadataCorrelationAndCopy(t *testing.T) {
	s, _ := testService(t)
	binding := serviceBinding()
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) { return []sandboxpolicy.Binding{binding}, nil }
	s.refresh(t.Context())
	binding.PodLabels["app"] = "mutated"
	v := sandboxpolicy.Verdict{ContainerID: binding.ContainerID, CgroupID: 42, PodUID: binding.PodUID, BindingPID: binding.PID, MountNamespace: binding.MountNamespace}
	got, ok := s.resolveBinding(v)
	if !ok || got.PodLabels["app"] != "test" {
		t.Fatal("metadata aliased caller")
	}
	v.CgroupID = 43
	if _, ok := s.resolveBinding(v); ok {
		t.Fatal("stale cgroup identity accepted")
	}
}
func TestServiceStartCloseAndNonblockingDiscovery(t *testing.T) {
	s, b := testService(t)
	var snapshots atomic.Int32
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) { snapshots.Add(1); return nil, nil }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for range 1000 {
		s.ContainerCallback(containercollection.PubSubEvent{})
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(t.Context(), time.Second)
	defer cleanupCancel()
	if err := s.Close(cleanupCtx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(cleanupCtx); err != nil || b.closes != 1 {
		t.Fatalf("close not idempotent: %v %d", err, b.closes)
	}
	if err := s.Start(ctx); err == nil {
		t.Fatal("restarted closed runtime")
	}
	if snapshots.Load() == 0 {
		t.Fatal("no initial snapshot")
	}
}
func TestServiceCloseBeforeStart(t *testing.T) {
	s, b := testService(t)
	if err := s.Close(t.Context()); err != nil || b.closes != 1 {
		t.Fatal(err)
	}
	if err := s.Start(t.Context()); err == nil {
		t.Fatal("closed service started")
	}
}
func TestNewServiceRequiresExplicitInputs(t *testing.T) {
	if _, err := NewService(t.Context(), ServiceOptions{}); err == nil {
		t.Fatal("missing explicit inputs accepted")
	}
}

// TestLegacyOwnerBudgetCap: the config default (IG's legacy Owner hard cap)
// constructs the node budget NewService hands the per-binding engine; one
// more is refused fail-closed, by the service before anything starts.
func TestLegacyOwnerBudgetCap(t *testing.T) {
	if _, err := newLegacyBudget(fullruntime.LegacyOwnerHardCap); err != nil {
		t.Fatalf("default owner budget: %v", err)
	}
	if _, err := newLegacyBudget(fullruntime.LegacyOwnerHardCap + 1); !errors.Is(err, fullruntime.ErrLegacyOwnerCap) {
		t.Fatalf("owner budget above the cap: %v", err)
	}
	if _, err := newLegacyBudget(0); err == nil {
		t.Fatal("empty owner budget accepted")
	}
}

// TestNewServiceOwnerCap: NewService refuses an owner count above IG's cap
// before touching the node, runtime or archive; the cap itself passes on to
// node identity (absent from the fake cluster).
func TestNewServiceOwnerCap(t *testing.T) {
	options := ServiceOptions{Kubernetes: kubefake.NewSimpleClientset(), Dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()), Containers: &containercollection.ContainerCollection{}, Tracers: &tracercollection.TracerCollection{}, NodeName: "node", AgentNamespace: "kubescape", ImageName: "enforce_exec:test", ImageArchive: "tracers.tar", ContainerdSocket: "/run/containerd/containerd.sock", ControlRoot: "/sys/fs/cgroup", MaxOwners: fullruntime.LegacyOwnerHardCap + 1}
	if _, err := NewService(t.Context(), options); !errors.Is(err, fullruntime.ErrLegacyOwnerCap) {
		t.Fatalf("above the cap: %v", err)
	}
	options.MaxOwners = fullruntime.LegacyOwnerHardCap
	if _, err := NewService(t.Context(), options); err == nil || !strings.Contains(err.Error(), "sandbox node identity") {
		t.Fatalf("at the cap: %v", err)
	}
}

func TestServiceRejectsReusedPodMetadata(t *testing.T) {
	s, _ := testService(t)
	b := serviceBinding()
	s.bindings[b.ContainerID] = b
	v := sandboxpolicy.Verdict{ContainerID: b.ContainerID, CgroupID: b.CgroupID, PodUID: "old-pod", BindingPID: b.PID, MountNamespace: b.MountNamespace}
	if _, ok := s.resolveBinding(v); ok {
		t.Fatal("old workload event attributed to replacement pod")
	}
	v.PodUID = b.PodUID
	v.BindingPID++
	if _, ok := s.resolveBinding(v); ok {
		t.Fatal("old init task accepted")
	}
}

func TestServiceCloseRetriesWithoutReleasingRuntime(t *testing.T) {
	s, b := testService(t)
	closes := 0
	s.closeRuntime = func() error { closes++; return nil }
	b.closeErr = errors.New("cleanup pending")
	if err := s.Close(t.Context()); err == nil {
		t.Fatal("cleanup error hidden")
	}
	if closes != 0 {
		t.Fatal("runtime released before cleanup")
	}
	b.closeErr = nil
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if b.closes != 2 || closes != 1 {
		t.Fatalf("cleanup retry: backend %d runtime %d", b.closes, closes)
	}
}

func TestDelayedWatchHintCannotResurrectDeletedPolicy(t *testing.T) {
	s, b := testService(t)
	binding := serviceBinding()
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) { return []sandboxpolicy.Binding{binding}, nil }
	s.refresh(t.Context())
	if b.replaces != 1 {
		t.Fatal("missing initial bind")
	}
	client := s.options.Dynamic
	old, err := client.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Get(t.Context(), "test", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Delete(t.Context(), "test", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	s.refresh(t.Context())
	if b.withdraws != 1 {
		t.Fatal("delete not withdrawn")
	}
	s.ModifyHandler(t.Context(), old)
	s.refresh(t.Context())
	if b.replaces != 1 {
		t.Fatal("delayed event revived deleted policy")
	}
}

type readinessCapture struct {
	reports []*api.SandboxPolicyNodeStatus
	failure error
}

func (w *readinessCapture) WriteStatus(_ context.Context, r *api.SandboxPolicyNodeStatus) error {
	w.reports = append(w.reports, r.DeepCopy())
	return w.failure
}
func TestReadinessWriterInputEpoch(t *testing.T) {
	var observed, snapshot atomic.Uint64
	inner := &readinessCapture{}
	writer := readinessWriter{inner: inner, observed: &observed, snapshot: &snapshot}
	report := &api.SandboxPolicyNodeStatus{Status: &api.NodeStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}}}
	if err := writer.WriteStatus(t.Context(), report); err != nil {
		t.Fatal(err)
	}
	observed.Add(1)
	inner.failure = errors.New("API unavailable")
	if err := writer.WriteStatus(t.Context(), report); !errors.Is(err, ErrInputsChanged) || !errors.Is(err, inner.failure) {
		t.Fatalf("barrier/write failure not preserved: %v", err)
	}
	last := inner.reports[len(inner.reports)-1]
	if last.Status.Conditions[0].Status != metav1.ConditionFalse || last.Status.Conditions[0].Reason != "InputsChanged" || !last.Status.Stale {
		t.Fatal("concurrent input still reported Ready")
	}
	if report.Status.Conditions[0].Status != metav1.ConditionTrue || report.Status.Stale {
		t.Fatal("writer mutated caller report")
	}
}
func TestServiceDrainsStartupChurnBeforeReady(t *testing.T) {
	s, b := testService(t)
	capture := &readinessCapture{}
	writer := readinessWriter{inner: capture, observed: &s.inputEpoch, snapshot: &s.snapshotEpoch}
	controller, err := sandboxpolicy.NewController(s.options.Dynamic, b, nil, writer, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	s.Controller = controller
	var snapshots atomic.Int32
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) {
		snapshots.Add(1)
		return []sandboxpolicy.Binding{serviceBinding()}, nil
	}
	b.onReplace = func() { b.onReplace = nil; s.ContainerCallback(containercollection.PubSubEvent{}) }
	if err = s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if snapshots.Load() < 2 || len(capture.reports) < 3 {
		t.Fatal("startup hint not replayed")
	}
	// Close's last report is AgentStopping; the one before it is the replay's.
	if stopping := capture.reports[len(capture.reports)-1]; stopping.Status.Conditions[0].Reason != sandboxpolicy.AgentStoppingReason {
		t.Fatalf("close did not report AgentStopping: %+v", stopping.Status.Conditions)
	}
	first, last := capture.reports[0], capture.reports[len(capture.reports)-2]
	if first.Status.Conditions[0].Status != metav1.ConditionFalse || first.Status.Conditions[0].Reason != "InputsChanged" {
		t.Fatal("premature Ready during native startup churn")
	}
	if last.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("stable replay never became Ready: %+v", last.Status.Conditions)
	}
	if last.Status.AppliedGeneration == 0 {
		t.Fatalf("Ready replay without appliedGeneration: %+v", last.Status)
	}
	if stopping := capture.reports[len(capture.reports)-1]; stopping.Status.AppliedGeneration != 0 {
		t.Fatalf("AgentStopping still claims appliedGeneration %d", stopping.Status.AppliedGeneration)
	}
}

type podBinderBackend struct {
	serviceTestBackend
	pods [][]sandboxpolicy.PodBinding
	err  error
}

func (b *podBinderBackend) BindPods(_ context.Context, pods []sandboxpolicy.PodBinding) error {
	b.pods = append(b.pods, pods)
	return b.err
}

func TestServiceBindsPodCgroups(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{sandboxpolicy.PolicyGVR: "SandboxPolicyList", sandboxpolicy.ClusterPolicyGVR: "ClusterSandboxPolicyList", sandboxpolicy.ClassesGVR: "SandboxPolicyClassesList"})
	p := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.SchemeGroupVersion.String(), "kind": "SandboxPolicy", "metadata": map[string]any{"name": "priv", "namespace": "ns", "uid": "policy-uid", "generation": int64(1)}, "spec": map[string]any{"selector": map[string]any{"podSelector": map[string]any{}}, "mode": "enforce", "containers": []any{"*"}, "privilege": map[string]any{"default": "allow", "rules": []any{map[string]any{"name": "no-chroot", "action": "deny", "target": map[string]any{"syscall": []any{"chroot"}}}}}}}}
	if _, err := client.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Create(t.Context(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	backend := &podBinderBackend{}
	controller, err := sandboxpolicy.NewController(client, backend, nil, nil, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.InitialSync(t.Context()); err != nil {
		t.Fatal(err)
	}
	// A running container of another pod gives the layout.
	containers := &containercollection.ContainerCollection{}
	running := &containercollection.Container{CgroupID: 500, CgroupV2: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podother_uid.slice/cri-containerd-x.scope"}
	running.Runtime.ContainerID = "x"
	running.K8s.PodUID = "other-uid"
	containers.AddContainer(running)
	want := "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podpod_uid.slice"
	var id uint64
	s := &Service{Controller: controller, backend: backend, options: ServiceOptions{Containers: containers, NodeName: "node"},
		scheduled: []sandboxpolicy.Binding{{PodUID: "pod-uid", Namespace: "ns", PodName: "pod", ContainerName: "app", Kind: "regular"}},
		qos:       map[types.UID]corev1.PodQOSClass{"pod-uid": corev1.PodQOSBestEffort},
		podCgroupID: func(path string) (uint64, error) {
			if path != want || id == 0 {
				return 0, errors.New("no such cgroup")
			}
			return id, nil
		}}
	last := func() []sandboxpolicy.PodBinding { return backend.pods[len(backend.pods)-1] }

	// The pod cgroup does not exist yet: nothing is bound, and the pod is polled.
	s.bindPods(t.Context())
	if len(last()) != 0 || !s.podPolling {
		t.Fatalf("missing cgroup: %+v polling=%v", last(), s.podPolling)
	}
	// The poll reuses the last plans: it binds once the cgroup appears,
	// and it reports a repeated BindPods error once.
	id = 77
	s.pollPods(t.Context())
	if got := last(); len(got) != 1 || got[0].CgroupID != 77 || s.podPolling {
		t.Fatalf("poll bind: %+v polling=%v", got, s.podPolling)
	}
	reports := 0
	s.options.OnError = func(error) { reports++ }
	backend.err = errors.New("busy")
	s.pollPods(t.Context())
	s.pollPods(t.Context())
	backend.err = nil
	s.options.OnError = nil
	if reports != 1 {
		t.Fatalf("a repeated poll error must be reported once: %d", reports)
	}
	s.bindPods(t.Context())
	if got := last(); len(got) != 1 || got[0].CgroupID != 77 || got[0].CgroupPath != want || len(got[0].Plan.Policies) != 1 || s.podPolling {
		t.Fatalf("bind: %+v polling=%v", got, s.podPolling)
	}
	// A container that runs in the pod cgroup itself keeps its own binding.
	id = 500
	s.bindPods(t.Context())
	if len(last()) != 0 {
		t.Fatalf("pod cgroup shared with a container must not be bound: %+v", last())
	}
	// Polling stops when the pod was first seen too long ago.
	id = 0
	s.podFirstSeen["pod-uid"] = time.Now().Add(-prepareInterval)
	s.bindPods(t.Context())
	if s.podPolling {
		t.Fatal("polling must stop after prepareInterval")
	}
	// An init container that the wildcard does not select: no pod binding.
	id = 77
	s.scheduled = append(s.scheduled, sandboxpolicy.Binding{PodUID: "pod-uid", Namespace: "ns", PodName: "pod", ContainerName: "setup", Kind: "init"})
	s.bindPods(t.Context())
	if len(last()) != 0 {
		t.Fatalf("mixed pod must not be bound: %+v", last())
	}
}

func TestServiceSettlesOnlyAfterConvergedRefresh(t *testing.T) {
	s, b := testService(t)
	binding := serviceBinding()
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) { return []sandboxpolicy.Binding{binding}, nil }
	s.refresh(t.Context())
	if err := s.Controller.LastError(); err != nil || b.settles != 1 {
		t.Fatalf("a converged refresh must settle once: settles %d, last error %v", b.settles, err)
	}
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) { return nil, errors.New("API unavailable") }
	s.refresh(t.Context())
	if b.settles != 1 {
		t.Fatalf("a failed refresh must not settle: %d", b.settles)
	}
	// Review 8: a policy that does not compile leaves the binding without
	// its full plan; "no plan" would not mean "no policy", so no settle.
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) { return []sandboxpolicy.Binding{binding}, nil }
	bad := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.SchemeGroupVersion.String(), "kind": "SandboxPolicy", "metadata": map[string]any{"name": "bad", "namespace": "ns", "uid": "bad-uid", "generation": int64(1)}, "spec": map[string]any{"selector": map[string]any{"podSelector": map[string]any{}}, "mode": "bogus", "containers": []any{"app"}}}}
	if _, err := s.options.Dynamic.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Create(t.Context(), bad, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	s.refresh(t.Context())
	if s.Controller.PlansComplete() || b.settles != 1 {
		t.Fatalf("a policy error must block the settle: complete %v settles %d", s.Controller.PlansComplete(), b.settles)
	}
}

func TestServiceReportsUnexpectedExporterExit(t *testing.T) {
	s, _ := testService(t)
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.exporter.Run(stopped); !errors.Is(err, context.Canceled) {
		t.Fatalf("prepare stopped exporter: %v", err)
	}
	reported := make(chan error, 1)
	s.options.OnError = func(err error) { reported <- err }
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) { return nil, nil }
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-reported:
		if err == nil || !strings.Contains(err.Error(), "sandbox verdict exporter") {
			t.Fatalf("missing exporter failure context: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unexpected exporter exit was not reported")
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

type preparerBackend struct {
	serviceTestBackend
	calls    int
	prepared []sandboxpolicy.Plan
}

func (b *preparerBackend) Prepare(_ context.Context, plans []sandboxpolicy.Plan) error {
	b.calls++
	b.prepared = plans
	return nil
}

// The first policies, and a policy change, are prepared right after Refresh
// loads them, so each policy has its slot before a pod matches it.
func TestServicePreparesPoliciesWhenLoaded(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{sandboxpolicy.PolicyGVR: "SandboxPolicyList", sandboxpolicy.ClusterPolicyGVR: "ClusterSandboxPolicyList", sandboxpolicy.ClassesGVR: "SandboxPolicyClassesList"})
	spec := func(syscall string) map[string]any {
		return map[string]any{"selector": map[string]any{"podSelector": map[string]any{}}, "mode": "enforce", "containers": []any{"*"}, "privilege": map[string]any{"default": "allow", "rules": []any{map[string]any{"name": "r", "action": "deny", "target": map[string]any{"syscall": []any{syscall}}}}}}
	}
	p := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.SchemeGroupVersion.String(), "kind": "SandboxPolicy", "metadata": map[string]any{"name": "priv", "namespace": "ns", "uid": "policy-uid", "generation": int64(1)}, "spec": spec("chroot")}}
	if _, err := client.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Create(t.Context(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	backend := &preparerBackend{}
	controller, err := sandboxpolicy.NewController(client, backend, nil, nil, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{Controller: controller, backend: backend, options: ServiceOptions{Dynamic: client, Kubernetes: fake.NewSimpleClientset(), PrivilegeImageName: "privilege", NodeName: "node"},
		snapshot: func(context.Context) ([]sandboxpolicy.Binding, error) { return nil, nil }, bindings: map[string]sandboxpolicy.Binding{}}
	rule := func() string {
		if len(backend.prepared) != 1 || len(backend.prepared[0].Policies) != 1 || backend.prepared[0].Policies[0].Privilege == nil {
			t.Fatalf("one policy plan expected: %+v", backend.prepared)
		}
		return backend.prepared[0].Policies[0].Privilege.Rules[0].Target.Syscall[0]
	}
	// Start: the first refresh loads the policy and prepares its slot.
	s.refresh(t.Context())
	if backend.calls != 1 || rule() != "chroot" {
		t.Fatalf("first load: calls=%d", backend.calls)
	}
	// No event: no preparation before prepareInterval.
	s.refresh(t.Context())
	if backend.calls != 1 {
		t.Fatalf("no event: calls=%d", backend.calls)
	}
	// A changed policy is prepared after the refresh that loads it.
	p.Object["spec"] = spec("mount")
	p.Object["metadata"].(map[string]any)["generation"] = int64(2)
	if _, err := client.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Update(t.Context(), p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	s.ModifyHandler(t.Context(), p)
	s.refresh(t.Context())
	if backend.calls != 2 || rule() != "mount" {
		t.Fatalf("policy change: calls=%d", backend.calls)
	}
}

// While a selected container is pending, refresh still publishes the correlated
// set for verdict correlation and binds it; the pending error stays visible.
func TestServiceRefreshBindsPartialSetWhilePending(t *testing.T) {
	s, b := testService(t)
	p, ns, containers := bindingFixtures()
	p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "sidecar"})
	p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: "sidecar", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}})
	late := *containers[0]
	late.Runtime.ContainerID = strings.Repeat("e", 64)
	late.K8s.ContainerName = "sidecar"
	late.CgroupID, late.Mntns, late.Runtime.ContainerPID = 200, 2000, 20000
	containers = append(containers, &late)
	client := kubefake.NewSimpleClientset(p, ns)
	// The callback runs under the controller lock, so it cannot ask the
	// controller for its selector; select what the test policy could select.
	s.snapshot = func(ctx context.Context) ([]sandboxpolicy.Binding, error) {
		return SnapshotSelectedBindingsFromContainers(ctx, client, containers, "node", func(b sandboxpolicy.Binding) bool { return b.Namespace == "ns" })
	}
	verdict := func(c *containercollection.Container) sandboxpolicy.Verdict {
		return sandboxpolicy.Verdict{ContainerID: c.Runtime.ContainerID, CgroupID: c.CgroupID, PodUID: "pod-uid", BindingPID: c.Runtime.ContainerPID, MountNamespace: c.Mntns}
	}
	for refresh := 0; refresh < 3; refresh++ {
		s.refresh(t.Context())
		var pending *sandboxpolicy.BindingPendingError
		if err := s.Controller.LastError(); !errors.As(err, &pending) || pending.Containers != 1 {
			t.Fatalf("refresh %d: pending not reported: %v", refresh, err)
		}
		// Each refresh re-replaces (attests) the same plan; it never withdraws.
		if b.replaces != refresh+1 || b.withdraws != 0 {
			t.Fatalf("refresh %d: correlated container not bound: %d replaces, %d withdrawals", refresh, b.replaces, b.withdraws)
		}
		if _, ok := s.resolveBinding(verdict(containers[0])); !ok {
			t.Fatalf("refresh %d: partial set not published", refresh)
		}
		if _, ok := s.resolveBinding(verdict(&late)); ok {
			t.Fatalf("refresh %d: pending container resolved", refresh)
		}
	}
	p.Status.ContainerStatuses[1].ContainerID = "containerd://" + late.Runtime.ContainerID
	p.Status.ContainerStatuses[1].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
	client = kubefake.NewSimpleClientset(p, ns)
	s.refresh(t.Context())
	if err := s.Controller.LastError(); err != nil {
		t.Fatalf("correlated snapshot still failing: %v", err)
	}
	if _, ok := s.resolveBinding(verdict(&late)); !ok || b.withdraws != 0 {
		t.Fatal("correlated container not published or a binding withdrawn")
	}
}

func TestServicePolicyWatchReplayDuringRefresh(t *testing.T) {
	for _, tc := range []struct {
		name       string
		send       func(*Service, context.Context, *unstructured.Unstructured)
		wantChange bool
	}{
		{name: "replayed add", send: func(s *Service, ctx context.Context, policy *unstructured.Unstructured) {
			s.AddHandler(ctx, policy)
		}},
		{name: "replayed modify", send: func(s *Service, ctx context.Context, policy *unstructured.Unstructured) {
			s.ModifyHandler(ctx, policy)
		}},
		{name: "new resource version", wantChange: true, send: func(s *Service, ctx context.Context, policy *unstructured.Unstructured) {
			policy.SetResourceVersion("101")
			s.AddHandler(ctx, policy)
		}},
		{name: "new UID", wantChange: true, send: func(s *Service, ctx context.Context, policy *unstructured.Unstructured) {
			policy.SetUID("replacement-uid")
			s.AddHandler(ctx, policy)
		}},
		{name: "missing resource version", wantChange: true, send: func(s *Service, ctx context.Context, policy *unstructured.Unstructured) {
			policy.SetResourceVersion("")
			s.AddHandler(ctx, policy)
		}},
		{name: "delete", wantChange: true, send: func(s *Service, ctx context.Context, policy *unstructured.Unstructured) {
			s.DeleteHandler(ctx, policy)
		}},
	} {
		for _, phase := range []string{"listing", "bindings"} {
			t.Run(tc.name+"/"+phase, func(t *testing.T) {
				s, backend := testService(t)
				ctx := t.Context()
				policies := s.options.Dynamic.Resource(sandboxpolicy.PolicyGVR).Namespace("ns")
				policy, err := policies.Get(ctx, "test", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				policy.SetResourceVersion("100")
				if _, err := policies.Update(ctx, policy, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				capture := &readinessCapture{}
				writer := readinessWriter{inner: capture, observed: &s.inputEpoch, snapshot: &s.snapshotEpoch}
				s.Controller, err = sandboxpolicy.NewController(s.options.Dynamic, backend, nil, writer, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
				if err != nil {
					t.Fatal(err)
				}
				snapshot := func(context.Context) ([]sandboxpolicy.Binding, error) {
					return []sandboxpolicy.Binding{serviceBinding()}, nil
				}
				s.snapshot = snapshot
				s.refresh(ctx)
				// A new list revision ensures the previous pass cannot identify the replay.
				policy.SetResourceVersion("102")
				if _, err := policies.Update(ctx, policy, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				if phase == "listing" {
					deliver := true
					s.options.Dynamic.(*dynamicfake.FakeDynamicClient).PrependReactor("list", sandboxpolicy.ClassesGVR.Resource, func(ktesting.Action) (bool, runtime.Object, error) {
						if deliver {
							tc.send(s, ctx, policy.DeepCopy())
							deliver = false
						}
						return false, nil, nil
					})
				} else {
					s.snapshot = func(ctx context.Context) ([]sandboxpolicy.Binding, error) {
						tc.send(s, ctx, policy.DeepCopy())
						return snapshot(ctx)
					}
				}
				s.refresh(ctx)
				queued := len(s.wake)
				s.snapshot = snapshot
				s.refresh(ctx)

				want := metav1.ConditionTrue
				if tc.wantChange {
					want = metav1.ConditionFalse
				}
				if len(capture.reports) != 3 {
					t.Fatalf("got %d reports, want 3", len(capture.reports))
				}
				got := capture.reports[1].Status.Conditions[0]
				if got.Status != want || (got.Reason == "InputsChanged") != tc.wantChange {
					t.Errorf("refresh during watch delivery: got %s (%s), want %s", got.Status, got.Reason, want)
				}
				if (queued != 0) != tc.wantChange {
					t.Errorf("queued %d refreshes, want a refresh: %t", queued, tc.wantChange)
				}
				for _, i := range []int{0, 2} {
					if condition := capture.reports[i].Status.Conditions[0]; condition.Status != metav1.ConditionTrue {
						t.Errorf("settled report %d: got %s (%s), want Ready", i, condition.Status, condition.Reason)
					}
				}
				if backend.withdraws != 0 {
					t.Errorf("withdrew enforcement %d times during watch delivery", backend.withdraws)
				}
			})
		}
	}
}

func TestServiceWatchRetriesFailedRefresh(t *testing.T) {
	for _, phase := range []string{"failed list", "during binding failure", "after binding failure"} {
		t.Run(phase, func(t *testing.T) {
			ctx := t.Context()
			s, backend := testService(t)
			policies := s.options.Dynamic.Resource(sandboxpolicy.PolicyGVR).Namespace("ns")
			policy, err := policies.Get(ctx, "test", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			policy.SetResourceVersion("101")
			if _, err := policies.Update(ctx, policy, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			fail := true
			if phase == "failed list" {
				s.options.Dynamic.(*dynamicfake.FakeDynamicClient).PrependReactor("list", sandboxpolicy.ClassesGVR.Resource, func(ktesting.Action) (bool, runtime.Object, error) {
					if fail {
						s.AddHandler(ctx, policy)
						return true, nil, errors.New("classes unavailable")
					}
					return false, nil, nil
				})
			}
			s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) {
				if fail {
					if phase == "during binding failure" {
						s.AddHandler(ctx, policy)
					}
					return nil, errors.New("bindings unavailable")
				}
				return []sandboxpolicy.Binding{serviceBinding()}, nil
			}
			s.refresh(ctx)
			if backend.replaces != 0 || s.Controller.LastError() == nil {
				t.Fatal("expected failed refresh")
			}
			fail = false
			if phase == "after binding failure" {
				if len(s.wake) != 0 {
					t.Fatal("unexpected wake before watch delivery")
				}
				s.AddHandler(ctx, policy)
			}
			select {
			case <-s.wake:
				s.refresh(ctx)
			default:
				t.Fatal("watch did not queue retry")
			}
			if backend.replaces != 1 || s.Controller.LastError() != nil {
				t.Fatalf("retry: replacements=%d error=%v", backend.replaces, s.Controller.LastError())
			}
		})
	}
}
