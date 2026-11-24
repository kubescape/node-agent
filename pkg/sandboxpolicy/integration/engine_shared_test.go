package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type capturingStatusWriter struct{ got *api.SandboxPolicyNodeStatus }

func (w *capturingStatusWriter) WriteStatus(_ context.Context, r *api.SandboxPolicyNodeStatus) error {
	w.got = r
	return nil
}

type fakeSharedHealthEngine struct {
	igbackend.FullEngine
	health igbackend.SharedNodeHealth
}

func (e fakeSharedHealthEngine) Health() igbackend.SharedNodeHealth { return e.health }

func TestEngineStatusWriterAppliesSharedHealth(t *testing.T) {
	inner := &capturingStatusWriter{}
	// A non-shared engine's writes are unchanged.
	if w := engineStatusWriter(nil, inner); w != sandboxpolicy.StatusWriter(inner) {
		t.Fatalf("non-shared engine wrapped: %T", w)
	}
	write := func(health igbackend.SharedNodeHealth) (map[string]metav1.Condition, *api.SandboxPolicyNodeStatus) {
		w := engineStatusWriter(fakeSharedHealthEngine{health: health}, inner)
		report := &api.SandboxPolicyNodeStatus{Status: &api.NodeStatus{ObservedGeneration: 4, LastReported: metav1.Now(), Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}, {Type: "ActiveRevision", Status: metav1.ConditionTrue}}}}
		if err := w.WriteStatus(context.Background(), report); err != nil {
			t.Fatal(err)
		}
		if report.Status.Conditions[0].Status != metav1.ConditionTrue {
			t.Fatal("caller's report mutated")
		}
		conditions := map[string]metav1.Condition{}
		for _, c := range inner.got.Status.Conditions {
			conditions[c.Type] = c
		}
		if conditions["ActiveRevision"].Type == "" {
			t.Fatalf("conditions %+v", inner.got.Status.Conditions)
		}
		return conditions, report
	}
	// Qualification: Ready stays False; loss is Degraded.
	conditions, _ := write(igbackend.SharedNodeHealth{Qualification: true, Started: true, Ready: fmt.Errorf("loss: %w", fullruntime.ErrSharedVerdictEventLoss), FailClosed: fullruntime.SharedFailClosedHealth{State: fullruntime.SharedFailClosedHealthy}})
	if ready, degraded := conditions["Ready"], conditions["Degraded"]; ready.Status != metav1.ConditionFalse || ready.ObservedGeneration != 4 || degraded.Status != metav1.ConditionTrue || degraded.Reason != "VerdictEventLoss" {
		t.Fatalf("qualification conditions %+v", conditions)
	}
	// Product: a Ready node keeps the controller's Ready; loss is Degraded only.
	product := igbackend.SharedNodeHealth{Started: true, Degraded: fmt.Errorf("loss: %w", fullruntime.ErrSharedVerdictEventLoss), FailClosed: fullruntime.SharedFailClosedHealth{State: fullruntime.SharedFailClosedHealthy}}
	conditions, _ = write(product)
	if ready, degraded := conditions["Ready"], conditions["Degraded"]; ready.Status != metav1.ConditionTrue || ready.Reason != "Reconciled" || degraded.Status != metav1.ConditionTrue || degraded.Reason != "VerdictEventLoss" {
		t.Fatalf("product conditions %+v", conditions)
	}
	// A product node that is not Ready makes Ready False.
	product.Ready = fmt.Errorf("%w: reaper", fullruntime.ErrSharedNodeNotReady)
	conditions, _ = write(product)
	if ready := conditions["Ready"]; ready.Status != metav1.ConditionFalse || ready.Reason != "SharedNodeNotReady" || ready.ObservedGeneration != 4 {
		t.Fatalf("product NotReady %+v", ready)
	}
}

// The shared engine's health applies only to policies with exec rules; for
// those, an existing Degraded (another section's) is kept and merged, and a
// NotReady node still forces Ready False.
func TestEngineStatusWriterScopesToExecPolicies(t *testing.T) {
	inner := &capturingStatusWriter{}
	unavailable := igbackend.SharedNodeHealth{Unavailable: fmt.Errorf("no image entry: %w", fullruntime.ErrSharedNativeUnavailable)}
	notReady := igbackend.SharedNodeHealth{Started: true, Ready: fmt.Errorf("%w: reaper", fullruntime.ErrSharedNodeNotReady), Degraded: fmt.Errorf("loss: %w", fullruntime.ErrSharedVerdictEventLoss), FailClosed: fullruntime.SharedFailClosedHealth{State: fullruntime.SharedFailClosedHealthy}}
	ready := igbackend.SharedNodeHealth{Started: true, Degraded: notReady.Degraded, FailClosed: notReady.FailClosed}
	sectionDegraded := metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue, Reason: "FailClosedRecent,WitnessUnknown", Message: "file section: fail-closed recently"}
	write := func(ctx context.Context, health igbackend.SharedNodeHealth, conditions ...metav1.Condition) map[string]metav1.Condition {
		t.Helper()
		report := &api.SandboxPolicyNodeStatus{Status: &api.NodeStatus{ObservedGeneration: 4, LastReported: metav1.Now(), Conditions: append([]metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}}, conditions...)}}
		if err := engineStatusWriter(fakeSharedHealthEngine{health: health}, inner).WriteStatus(ctx, report); err != nil {
			t.Fatal(err)
		}
		out := map[string]metav1.Condition{}
		for _, c := range inner.got.Status.Conditions {
			out[c.Type] = c
		}
		return out
	}
	noExec := sandboxpolicy.WithPolicyExec(context.Background(), false)
	exec := sandboxpolicy.WithPolicyExec(context.Background(), true)

	// No exec rules: Ready and Degraded untouched, whatever the node.
	for _, health := range []igbackend.SharedNodeHealth{unavailable, {}, notReady} {
		c := write(noExec, health, sectionDegraded)
		if c["Ready"].Status != metav1.ConditionTrue || c["Ready"].Reason != "Reconciled" || c["Degraded"] != sectionDegraded || len(c) != 2 {
			t.Fatalf("non-exec policy rewritten: %+v", c)
		}
	}
	// Exec policy, existing Degraded True: kept, ours merged.
	c := write(exec, ready, sectionDegraded)
	if d := c["Degraded"]; d.Status != metav1.ConditionTrue || d.Reason != "FailClosedRecent,WitnessUnknown,VerdictEventLoss" || !strings.HasPrefix(d.Message, sectionDegraded.Message+"; ") || !strings.Contains(d.Message, "loss") {
		t.Fatalf("merged degraded %+v", d)
	}
	if c["Ready"].Status != metav1.ConditionTrue || c["Ready"].Reason != "Reconciled" {
		t.Fatalf("ready %+v", c["Ready"])
	}
	// Ours not Degraded: the existing one stays as it was.
	healthy := ready
	healthy.Degraded = nil
	if c := write(exec, healthy, sectionDegraded); c["Degraded"] != sectionDegraded {
		t.Fatalf("existing degraded replaced: %+v", c["Degraded"])
	}
	// Exec NotReady still forces Ready False (and keeps the section's Degraded).
	c = write(exec, notReady, sectionDegraded)
	if c["Ready"].Status != metav1.ConditionFalse || c["Ready"].Reason != "SharedNodeNotReady" || !strings.HasPrefix(c["Degraded"].Reason, "FailClosedRecent,WitnessUnknown,") {
		t.Fatalf("exec NotReady %+v", c)
	}
	// Unavailable engine: Ready False for an exec policy; an unknown policy
	// counts as exec (fail-closed).
	for _, ctx := range []context.Context{exec, context.Background()} {
		if c := write(ctx, unavailable); c["Ready"].Status != metav1.ConditionFalse || c["Ready"].Reason != "SharedEngineUnavailable" {
			t.Fatalf("unavailable %+v", c["Ready"])
		}
	}
}
