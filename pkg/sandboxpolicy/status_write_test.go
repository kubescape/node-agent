package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// statusWriteHarness writes one policy's report through DynamicStatusWriter
// at chosen report times and counts the status updates that reach the API.
type statusWriteHarness struct {
	t      *testing.T
	ctx    context.Context
	writer DynamicStatusWriter
	report *api.SandboxPolicyNodeStatus
	start  time.Time
	read   func() api.SandboxPolicyNodeStatus
	writes func() int
}

func newStatusWriteHarness(t *testing.T) *statusWriteHarness {
	t.Helper()
	ctx := context.Background()
	c, _, _, client := setup(t)
	r := c.report(parseTypedPolicy(t, policy("policy", "ns")), nil)
	h := &statusWriteHarness{t: t, ctx: ctx, writer: DynamicStatusWriter{Client: client}, report: r,
		start: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)}
	h.read = func() api.SandboxPolicyNodeStatus {
		t.Helper()
		current, err := client.Resource(NodeStatusGVR).Namespace("ns").Get(ctx, r.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var stored api.SandboxPolicyNodeStatus
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(current.Object, &stored); err != nil {
			t.Fatal(err)
		}
		return stored
	}
	h.writes = func() int {
		n := 0
		for _, action := range client.Actions() {
			if action.GetVerb() == "update" && action.GetSubresource() == "status" {
				n++
			}
		}
		return n
	}
	return h
}

// writeAt writes the report as built at start+offset and returns whether an
// UpdateStatus reached the API.
func (h *statusWriteHarness) writeAt(offset time.Duration) bool {
	h.t.Helper()
	before := h.writes()
	h.report.Status.LastReported = metav1.NewTime(h.start.Add(offset))
	if err := h.writer.WriteStatus(h.ctx, h.report); err != nil {
		h.t.Fatal(err)
	}
	return h.writes() > before
}

// An idle node writes a report once, then only at the heartbeat.
func TestDynamicStatusWriterSkipsUnchangedUntilHeartbeat(t *testing.T) {
	h := newStatusWriteHarness(t)
	if !h.writeAt(0) {
		t.Fatal("first report not written")
	}
	for pass := 1; pass < int(StatusHeartbeat/(5*time.Second)); pass++ {
		if h.writeAt(time.Duration(pass) * 5 * time.Second) {
			t.Fatalf("unchanged report written at pass %d", pass)
		}
	}
	if got := h.read().Status.LastReported.Time; !got.Equal(h.start) {
		t.Fatalf("lastReported %v moved without a write", got)
	}
	if !h.writeAt(StatusHeartbeat) {
		t.Fatal("heartbeat not written")
	}
	if got := h.read().Status.LastReported.Time; !got.Equal(h.start.Add(StatusHeartbeat)) {
		t.Fatalf("heartbeat lastReported %v", got)
	}
	if h.writeAt(StatusHeartbeat + 5*time.Second) {
		t.Fatal("unchanged report written right after the heartbeat")
	}
}

// A change of state is written in the same pass, whatever the heartbeat.
func TestDynamicStatusWriterWritesStateChangeAtOnce(t *testing.T) {
	changes := map[string]func(*api.NodeStatus){
		"ready status": func(s *api.NodeStatus) { s.Conditions[0].Status = metav1.ConditionFalse },
		"ready reason": func(s *api.NodeStatus) { s.Conditions[0].Reason = "InputsChanged" },
		"message text": func(s *api.NodeStatus) { s.Conditions[0].Message = "another message" },
		"generation":   func(s *api.NodeStatus) { s.ObservedGeneration++ },
		"stale":        func(s *api.NodeStatus) { s.Stale = !s.Stale },
		"error":        func(s *api.NodeStatus) { s.Error = "boom" },
		"tier":         func(s *api.NodeStatus) { s.Tier = "none" },
		"degraded": func(s *api.NodeStatus) {
			s.Degraded = append(s.Degraded, api.DegradedRule{Rule: "r", Requested: "enforce", Effective: "audit", Reason: "x"})
		},
		"new condition": func(s *api.NodeStatus) {
			s.Conditions = append(s.Conditions, metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue, Reason: "FailClosed", Message: "m", LastTransitionTime: metav1.Now()})
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			h := newStatusWriteHarness(t)
			if !h.writeAt(0) {
				t.Fatal("first report not written")
			}
			change(h.report.Status)
			if !h.writeAt(5 * time.Second) {
				t.Fatal("state change not written in the same pass")
			}
		})
	}
}

// A condition message whose only change is a count is written at most once per
// StatusCountCoalesce; any other change still goes out at once.
func TestDynamicStatusWriterCoalescesCountOnlyMessages(t *testing.T) {
	h := newStatusWriteHarness(t)
	h.report.Status.Conditions[0].Message = "3 denies in the last minute have no verdict"
	if !h.writeAt(0) {
		t.Fatal("first report not written")
	}
	h.report.Status.Conditions[0].Message = "7 denies in the last minute have no verdict"
	if h.writeAt(5 * time.Second) {
		t.Fatal("count-only change written before the coalescing interval")
	}
	h.report.Status.Conditions[0].Message = "12 denies in the last minute have no verdict"
	if !h.writeAt(StatusCountCoalesce) {
		t.Fatal("count-only change not written after the coalescing interval")
	}
	if got := h.read().Status.Conditions[0].Message; got != "12 denies in the last minute have no verdict" {
		t.Fatalf("stored message %q", got)
	}
	h.report.Status.Conditions[0].Message = "13 denies in the last minute have no verdict"
	if h.writeAt(StatusCountCoalesce + 5*time.Second) {
		t.Fatal("count-only change written again inside the interval")
	}
	h.report.Status.Conditions[0].Reason = "Unconfirmed"
	if !h.writeAt(StatusCountCoalesce + 10*time.Second) {
		t.Fatal("reason change not written at once")
	}
}

// A stored lastReported in the future (clock step) does not stop the writes.
func TestDynamicStatusWriterWritesWhenStoredReportIsAhead(t *testing.T) {
	h := newStatusWriteHarness(t)
	if !h.writeAt(time.Hour) {
		t.Fatal("first report not written")
	}
	if !h.writeAt(0) {
		t.Fatal("report behind the stored lastReported not written")
	}
}

// The controller's 5 s reconcile rebuilds every report; with nothing changed on
// the node the real writer sends one status update, not one per pass, and a
// binding change is written in the next pass.
func TestControllerIdleReconcileWritesOnce(t *testing.T) {
	ctx := context.Background()
	c, _, _, client := setup(t, policy("policy", "ns"))
	c.writer = DynamicStatusWriter{Client: client}
	statusWrites := func() int {
		n := 0
		for _, action := range client.Actions() {
			if action.GetVerb() == "update" && action.GetSubresource() == "status" {
				n++
			}
		}
		return n
	}
	if err := c.SetBindings(ctx, []Binding{binding()}); err != nil {
		t.Fatal(err)
	}
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	first := statusWrites()
	if first == 0 {
		t.Fatal("initial report not written")
	}
	for pass := 0; pass < 10; pass++ {
		if err := c.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := statusWrites(); got != first {
		t.Fatalf("idle reconciles wrote %d status updates, want 0", got-first)
	}
	if err := c.SetBindings(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := statusWrites(); got == first {
		t.Fatal("binding change not written")
	}
}

// The controller joins binding errors in map order; the report's error text
// must not depend on that order, else a lasting failure on two bindings is
// rewritten on every pass.
func TestReportErrorTextIgnoresJoinOrder(t *testing.T) {
	c, _, _, _ := setup(t)
	p := parseTypedPolicy(t, policy("policy", "ns"))
	a := fmt.Errorf("bind container aaa: %w", errors.New("refused"))
	b := errors.New("bind container bbb: io_uring rings held\n  detail line")
	wrapped := fmt.Errorf("prepare: %w; %w", a, b) // not a join: kept whole
	one := c.report(p, errors.Join(errors.Join(a, wrapped), b))
	two := c.report(p, errors.Join(b, errors.Join(wrapped, a)))
	if one.Status.Error != two.Status.Error {
		t.Fatalf("error text depends on join order:\n%q\n%q", one.Status.Error, two.Status.Error)
	}
	if !strings.Contains(one.Status.Error, wrapped.Error()) || !strings.Contains(one.Status.Error, "bind container bbb: io_uring rings held\n  detail line") {
		t.Fatalf("error text lost a cause or split a multi-line one: %q", one.Status.Error)
	}
}

// ActiveRevision and AdoptedLastGood name installed generations, not counts: a
// change in their numbers is written in the same pass.
func TestDynamicStatusWriterWritesIdentityMessagesAtOnce(t *testing.T) {
	for _, condition := range []string{"ActiveRevision", "AdoptedLastGood"} {
		t.Run(condition, func(t *testing.T) {
			h := newStatusWriteHarness(t)
			h.report.Status.Conditions = append(h.report.Status.Conditions, metav1.Condition{Type: condition, Status: metav1.ConditionTrue, Reason: "Installed", Message: "generation=2 scope=subtree", LastTransitionTime: metav1.Now()})
			if !h.writeAt(0) {
				t.Fatal("first report not written")
			}
			h.report.Status.Conditions[len(h.report.Status.Conditions)-1].Message = "generation=3 scope=subtree"
			if !h.writeAt(5 * time.Second) {
				t.Fatalf("%s generation change not written in the same pass", condition)
			}
		})
	}
}

// Reconcile joins one binding failure at a time, a left-nested errors.Join
// chain; every cause is kept once, in sorted order.
func TestStableErrorTextFlattensDeepJoin(t *testing.T) {
	const n = 3000
	var err error
	for i := n - 1; i >= 0; i-- {
		err = errors.Join(err, fmt.Errorf("binding %05d failed", i))
	}
	lines := strings.Split(stableErrorText(err), "\n")
	if len(lines) != n || lines[0] != "binding 00000 failed" || lines[n-1] != fmt.Sprintf("binding %05d failed", n-1) {
		t.Fatalf("%d lines, first %q last %q", len(lines), lines[0], lines[len(lines)-1])
	}
}
