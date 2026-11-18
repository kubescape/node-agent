package integration

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/utils"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// stopRecordingWriter records every write (policy UID, exec flag, Ready).
type stopRecordingWriter struct {
	mu      sync.Mutex
	writes  []stopWrite
	block   chan struct{} // non-nil: AgentStopping writes block until closed
	entered chan struct{}
	// blockReady (non-nil): Ready True writes block until it is closed.
	blockReady   chan struct{}
	readyEntered chan struct{}
}

type stopWrite struct {
	uid        string
	exec       bool
	conditions []metav1.Condition
}

func (w *stopRecordingWriter) WriteStatus(ctx context.Context, r *api.SandboxPolicyNodeStatus) error {
	if w.block != nil && r.Status.Conditions[0].Reason == sandboxpolicy.AgentStoppingReason {
		select {
		case w.entered <- struct{}{}:
		default:
		}
		<-w.block // ignores ctx: a writer that hangs
	}
	if w.blockReady != nil && r.Status.Conditions[0].Status == metav1.ConditionTrue {
		select {
		case w.readyEntered <- struct{}{}:
		default:
		}
		<-w.blockReady
	}
	hasExec, _ := sandboxpolicy.PolicyExecFrom(ctx)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, stopWrite{uid: string(r.Spec.PolicyRef.UID), exec: hasExec, conditions: append([]metav1.Condition(nil), r.Status.Conditions...)})
	return nil
}

func (w *stopRecordingWriter) snapshot() []stopWrite {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]stopWrite(nil), w.writes...)
}

// stopTestService is testService with writer, plus a policy without exec
// rules and an Off exec policy.
func stopTestService(t *testing.T, writer sandboxpolicy.StatusWriter) (*Service, *serviceTestBackend, *[]error) {
	t.Helper()
	s, b := testService(t)
	for name, spec := range map[string]map[string]any{
		"no-exec":  {"selector": map[string]any{"podSelector": map[string]any{}}, "mode": "enforce", "containers": []any{"app"}},
		"exec-off": {"selector": map[string]any{"podSelector": map[string]any{}}, "mode": "off", "containers": []any{"app"}, "exec": map[string]any{"default": "deny"}},
	} {
		p := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.SchemeGroupVersion.String(), "kind": "SandboxPolicy", "metadata": map[string]any{"name": name, "namespace": "ns", "uid": name, "generation": int64(1)}, "spec": spec}}
		if _, err := s.options.Dynamic.Resource(sandboxpolicy.PolicyGVR).Namespace("ns").Create(t.Context(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	controller, err := sandboxpolicy.NewController(s.options.Dynamic, b, nil, writer, sandboxpolicy.Options{Node: api.NodeReference{Name: "node", UID: "node-uid"}, AgentNamespace: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	s.Controller = controller
	var reported []error
	s.options.OnError = func(err error) { reported = append(reported, err) }
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) {
		return []sandboxpolicy.Binding{serviceBinding()}, nil
	}
	return s, b, &reported
}

// A graceful Close reports Ready False (AgentStopping) for exec policies only,
// before the backend withdraws enforcement, keeps ActiveRevision, and
// writes nothing afterwards.
func TestServiceCloseReportsAgentStopping(t *testing.T) {
	writer := &stopRecordingWriter{}
	s, b, _ := stopTestService(t, writer)
	s.refresh(t.Context())
	if b.replaces != 1 {
		t.Fatalf("replaces %d", b.replaces)
	}
	before := len(writer.snapshot())
	var stoppingBeforeWithdraw int
	b.onClose = func() {
		for _, w := range writer.snapshot()[before:] {
			if w.conditions[0].Reason == sandboxpolicy.AgentStoppingReason {
				stoppingBeforeWithdraw++
			}
		}
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	stopping := writer.snapshot()[before:]
	if len(stopping) != 1 || stopping[0].uid != "policy-uid" || !stopping[0].exec || stoppingBeforeWithdraw != 1 || b.closes != 1 {
		t.Fatalf("stopping writes %+v (before withdraw %d, closes %d)", stopping, stoppingBeforeWithdraw, b.closes)
	}
	ready := stopping[0].conditions[0]
	if ready.Type != "Ready" || ready.Status != metav1.ConditionFalse || ready.Reason != "AgentStopping" || ready.Message != "node-agent is stopping; enforcement is withdrawn until it restarts" {
		t.Fatalf("ready %+v", ready)
	}
	if len(stopping[0].conditions) != 2 || stopping[0].conditions[1].Type != "ActiveRevision" || stopping[0].conditions[1].Status != metav1.ConditionTrue {
		t.Fatalf("active revision not kept: %+v", stopping[0].conditions)
	}
	// No status is written after Close, whatever reconciles.
	after := len(writer.snapshot())
	s.refresh(t.Context())
	_ = s.Controller.Reconcile(t.Context())
	_ = s.Controller.ReportBindingFailure(t.Context(), errors.New("late"))
	if got := len(writer.snapshot()); got != after {
		t.Fatalf("%d writes after Close", got-after)
	}
	// A retried Close does not report again.
	if err := s.Close(t.Context()); err != nil || len(writer.snapshot()) != after {
		t.Fatalf("second close %v", err)
	}
}

// A writer that hangs (ignoring its context) does not block Close beyond
// AgentStoppingTimeout: the failure is reported and shutdown continues.
func TestServiceCloseBoundsAgentStopping(t *testing.T) {
	writer := &stopRecordingWriter{}
	s, b, reported := stopTestService(t, writer)
	s.refresh(t.Context())
	writer.block, writer.entered = make(chan struct{}), make(chan struct{}, 1)
	defer close(writer.block)
	start := time.Now()
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed < AgentStoppingTimeout || elapsed > AgentStoppingTimeout+2*time.Second {
		t.Fatalf("close took %s", elapsed)
	}
	select {
	case <-writer.entered:
	default:
		t.Fatal("AgentStopping write never started")
	}
	if b.closes != 1 || len(*reported) == 0 || !errors.Is((*reported)[len(*reported)-1], context.DeadlineExceeded) {
		t.Fatalf("closes %d reported %v", b.closes, *reported)
	}
}

// A reconciliation blocked inside the writer while reporting Ready True holds
// the controller lock past Close's wait: Close still returns within
// AgentStoppingTimeout, and once the blocked write lands, AgentStopping is
// written after it on its own context, so the last report is AgentStopping.
func TestServiceCloseAgentStoppingAfterSlowReconcile(t *testing.T) {
	writer := &stopRecordingWriter{}
	s, b, reported := stopTestService(t, writer)
	s.refresh(t.Context())
	writer.blockReady, writer.readyEntered = make(chan struct{}), make(chan struct{}, 1)
	reconciled := make(chan struct{})
	go func() {
		defer close(reconciled)
		_ = s.Controller.Reconcile(context.Background()) // the backend is closed under it
	}()
	<-writer.readyEntered
	start := time.Now()
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < AgentStoppingTimeout || elapsed > AgentStoppingTimeout+2*time.Second {
		t.Fatalf("close took %s", elapsed)
	}
	if b.closes != 1 || len(*reported) == 0 {
		t.Fatalf("closes %d reported %v", b.closes, *reported)
	}
	close(writer.blockReady)
	<-reconciled
	deadline := time.Now().Add(5 * time.Second)
	for {
		writes := writer.snapshot()
		last := writes[len(writes)-1]
		if last.conditions[0].Reason == sandboxpolicy.AgentStoppingReason {
			if last.uid != "policy-uid" || last.conditions[0].Status != metav1.ConditionFalse {
				t.Fatalf("last report %+v", last)
			}
			// The blocked Ready True write (whichever policy the reconcile was
			// writing) landed before it; no Ready True follows it.
			if prior := writes[len(writes)-2]; prior.conditions[0].Status != metav1.ConditionTrue {
				t.Fatalf("report before AgentStopping %+v", prior)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("last report is not AgentStopping: %+v", last)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A Start that unwinds before launching its loop (here a snapshot that panics
// during the initial drain) leaves Close nothing to wait for: Close returns
// promptly, still reports AgentStopping and withdraws.
func TestServiceCloseAfterStartPanics(t *testing.T) {
	writer := &stopRecordingWriter{}
	s, b, _ := stopTestService(t, writer)
	s.refresh(t.Context())
	before := len(writer.snapshot())
	s.snapshot = func(context.Context) ([]sandboxpolicy.Binding, error) { panic("snapshot panicked") }
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("Start did not panic")
			}
		}()
		_ = s.Start(context.Background())
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > AgentStoppingTimeout {
		t.Fatalf("close took %s", elapsed)
	}
	stopping := 0
	for _, w := range writer.snapshot()[before:] {
		if w.conditions[0].Reason == sandboxpolicy.AgentStoppingReason {
			stopping++
		}
	}
	if stopping != 1 || b.closes != 1 {
		t.Fatalf("AgentStopping writes %d, backend closes %d", stopping, b.closes)
	}
}

// closeVerdictReceiver blocks each verdict on gate (nil: never blocks).
type closeVerdictReceiver struct {
	gate     chan struct{}
	received chan utils.K8sEvent
}

func (r *closeVerdictReceiver) ReportEvent(_ utils.EventType, event utils.K8sEvent) {
	if r.gate != nil {
		<-r.gate
	}
	r.received <- event
}

// startedWithdrawalService is a started service whose backend reports n
// verdicts to the exporter while Close withdraws enforcement.
func startedWithdrawalService(t *testing.T, receiver *closeVerdictReceiver, n int) (*Service, *serviceTestBackend, *[]error) {
	t.Helper()
	s, b, reported := stopTestService(t, &stopRecordingWriter{})
	receivers := &maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]{}
	receivers.Set(utils.ExecAuthorizationEventType, mapset.NewSet[containerwatcher.GenericEventReceiver](receiver))
	exporter, err := sandboxpolicy.NewVerdictExporter(sandboxpolicy.ExporterOptions{Capacity: 8, Receivers: receivers})
	if err != nil {
		t.Fatal(err)
	}
	s.exporter = exporter
	var mu sync.Mutex
	s.options.OnError = func(err error) { mu.Lock(); defer mu.Unlock(); *reported = append(*reported, err) }
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.onClose = func() {
		for range n {
			if err := s.exporter.ReportVerdict(context.Background(), sandboxpolicy.Verdict{ContainerID: "exact-id", CgroupID: 42}); err != nil {
				t.Errorf("verdict during withdrawal refused: %v", err)
			}
		}
	}
	return s, b, reported
}

// A verdict reported while Close withdraws enforcement reaches the receiver:
// the exporter is stopped only after withdrawal, and drains its queue.
func TestServiceCloseDeliversVerdictsReportedDuringWithdrawal(t *testing.T) {
	receiver := &closeVerdictReceiver{received: make(chan utils.K8sEvent, 4)}
	s, b, _ := startedWithdrawalService(t, receiver, 2)
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if b.closes != 1 || len(receiver.received) != 2 {
		t.Fatalf("backend closes %d, delivered %d of 2", b.closes, len(receiver.received))
	}
	if stats := s.ExporterStats(); stats.Enqueued != 2 || stats.Delivered != 2 || stats.Dropped != 0 {
		t.Fatalf("stats %+v", stats)
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// A receiver that never returns holds Close at most VerdictDrainTimeout, even
// with a much longer ctx: Close still releases the runtime, and the verdict
// queued behind it is counted dropped.
func TestServiceCloseBoundedByBlockedVerdictReceiver(t *testing.T) {
	receiver := &closeVerdictReceiver{gate: make(chan struct{}), received: make(chan utils.K8sEvent, 4)}
	defer close(receiver.gate)
	s, _, reported := startedWithdrawalService(t, receiver, 2)
	runtimeClosed := false
	s.closeRuntime = func() error { runtimeClosed = true; return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < sandboxpolicy.VerdictDrainTimeout || elapsed > sandboxpolicy.VerdictDrainTimeout+2*time.Second {
		t.Fatalf("close took %s", elapsed)
	}
	if !runtimeClosed {
		t.Fatal("runtime not released after a bounded drain")
	}
	if stats := s.ExporterStats(); stats.Delivered != 0 || stats.Dropped != 1 {
		t.Fatalf("stats %+v", stats)
	}
	found := false
	for _, err := range *reported {
		found = found || (strings.Contains(err.Error(), "sandbox verdict exporter drain") && errors.Is(err, context.DeadlineExceeded))
	}
	if !found {
		t.Fatalf("drain deadline not reported: %v", *reported)
	}
}

// Close with an already-expired ctx returns promptly without hanging on the
// loop or the exporter; a retried Close then completes the shutdown once.
func TestServiceCloseExpiredContextThenRetry(t *testing.T) {
	receiver := &closeVerdictReceiver{received: make(chan utils.K8sEvent, 4)}
	s, b, _ := startedWithdrawalService(t, receiver, 0)
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := s.Close(expired); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expired Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expired Close took %s", elapsed)
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatalf("retried Close: %v", err)
	}
	if b.closes != 1 {
		t.Fatalf("backend closes %d", b.closes)
	}
}

// Start returns only once the exporter's Run has claimed the start, so a Close
// right after Start drains verdicts reported during withdrawal instead of
// treating the exporter as never started and dropping them.
func TestServiceStartWaitsForExporterBeforeClose(t *testing.T) {
	receiver := &closeVerdictReceiver{received: make(chan utils.K8sEvent, 4)}
	s, _, _ := startedWithdrawalService(t, receiver, 2)
	select {
	case <-s.exporter.Started():
	default:
		t.Fatal("Start returned before the exporter claimed its start")
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if stats := s.ExporterStats(); stats.Delivered != 2 || stats.Dropped != 0 || len(receiver.received) != 2 {
		t.Fatalf("stats %+v", stats)
	}
}
