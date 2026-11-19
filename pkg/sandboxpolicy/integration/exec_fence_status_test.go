// Copyright 2026 The Kubescape authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fenceStatusProbe struct {
	refusal, snapshotError error
	snapshot               restartfence.Snapshot
}

func (p fenceStatusProbe) Refusal() error { return p.refusal }
func (p fenceStatusProbe) Snapshot() (restartfence.Snapshot, error) {
	return p.snapshot, p.snapshotError
}

type fenceStatusCapture struct{ last *api.SandboxPolicyNodeStatus }

func (c *fenceStatusCapture) WriteStatus(_ context.Context, report *api.SandboxPolicyNodeStatus) error {
	c.last = report
	return nil
}

func TestExecFenceStatusDoesNotInventReadinessOrOutages(t *testing.T) {
	report := &api.SandboxPolicyNodeStatus{Status: &api.NodeStatus{
		AppliedGeneration: 8,
		Conditions: []metav1.Condition{
			{Type: "Ready", Status: metav1.ConditionFalse, Reason: "ProductUnavailable"},
			{Type: "Degraded", Status: metav1.ConditionTrue, Reason: "OtherDegradation", Message: "retain me"},
		},
	}}
	inner := &fenceStatusCapture{}
	w := execFenceStatusWriter{inner: inner, fence: fenceStatusProbe{snapshot: restartfence.Snapshot{
		PerCgroup: map[uint64]restartfence.Totals{1: {Denied: 99, OutageDenied: 3, OutageAudit: 5}},
	}}}
	if err := w.WriteStatus(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	got := inner.last.Status
	if got.Conditions[0].Reason != "ProductUnavailable" || got.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatalf("outage summary changed readiness: %+v", got)
	}
	c := got.Conditions[1]
	if !strings.Contains(c.Reason, "OtherDegradation") || !strings.Contains(c.Reason, "AgentOutageExecs") ||
		!strings.Contains(c.Message, "3 denied") || strings.Contains(c.Message, "99 denied") {
		t.Fatalf("did not merge actual outage counters: %+v", c)
	}
	w.fence = fenceStatusProbe{refusal: errors.New("old ABI cannot be attested")}
	if err := w.WriteStatus(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	got = inner.last.Status
	if got.AppliedGeneration != 0 || got.Conditions[0].Reason != "ExecFenceAdoptionRefused" {
		t.Fatalf("adoption refusal asserted an unproven generation: %+v", got)
	}
	if report.Status.AppliedGeneration != 8 {
		t.Fatal("writer modified its caller's report")
	}
}
