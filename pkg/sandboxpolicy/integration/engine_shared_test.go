package integration

import (
	"context"
	"fmt"
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
		t.Fatalf("per-binding engine wrapped: %T", w)
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
