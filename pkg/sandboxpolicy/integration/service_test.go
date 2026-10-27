package integration

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

type serviceTestBackend struct {
	replaces, withdraws, closes int
	closeErr                    error
	onReplace                   func()
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
func (b *serviceTestBackend) Close(context.Context) error { b.closes++; return b.closeErr }
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
	return &Service{Controller: controller, backend: backend, exporter: exporter, closeRuntime: func() error { return nil }, options: ServiceOptions{Dynamic: client}, bindings: map[string]sandboxpolicy.Binding{}, done: make(chan struct{}), wake: make(chan struct{}, 1)}, backend
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
	if snapshots.Load() < 2 || len(capture.reports) < 2 {
		t.Fatal("startup hint not replayed")
	}
	first, last := capture.reports[0], capture.reports[len(capture.reports)-1]
	if first.Status.Conditions[0].Status != metav1.ConditionFalse || first.Status.Conditions[0].Reason != "InputsChanged" {
		t.Fatal("premature Ready during native startup churn")
	}
	if last.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("stable replay never became Ready: %+v", last.Status.Conditions)
	}
}
