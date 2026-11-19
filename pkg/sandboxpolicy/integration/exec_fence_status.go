// Copyright 2026 The Kubescape authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type execFenceStatus interface {
	Refusal() error
	Snapshot() (restartfence.Snapshot, error)
}

type execFenceStatusWriter struct {
	inner sandboxpolicy.StatusWriter
	fence execFenceStatus
}

func (w execFenceStatusWriter) WriteStatus(ctx context.Context, report *api.SandboxPolicyNodeStatus) error {
	if report == nil || report.Status == nil {
		return w.inner.WriteStatus(ctx, report)
	}
	if exec, known := sandboxpolicy.PolicyExecFrom(ctx); known && !exec {
		return w.inner.WriteStatus(ctx, report)
	}
	copy := report.DeepCopy()
	status := copy.Status
	if err := w.fence.Refusal(); err != nil {
		for i, c := range status.Conditions {
			if c.Type != "Ready" || c.Reason == sandboxpolicy.AgentStoppingReason || c.Reason == sandboxpolicy.AgentStoppingUnconfirmedReason {
				continue
			}
			c.Status = metav1.ConditionFalse
			c.Reason = "ExecFenceAdoptionRefused"
			c.Message = fmt.Sprintf("exec fence adoption refused; product enforcement cannot be reported: %v", err)
			status.Truncated = sandboxpolicy.BoundCondition(&c) || status.Truncated
			status.Conditions[i] = c
		}
		status.AppliedGeneration = 0
		return w.inner.WriteStatus(ctx, copy)
	}
	if reclaimer, ok := w.fence.(interface{ ReclamationError() error }); ok {
		if err := reclaimer.ReclamationError(); err != nil {
			setExecFenceDegraded(status, "ExecFenceGCUnavailable", fmt.Sprintf("exec fence cgroup exit proof unavailable; retaining affected rows: %v", err))
		}
	}
	snapshot, err := w.fence.Snapshot()
	if err != nil {
		setExecFenceDegraded(status, "AgentOutageExecsUnavailable", fmt.Sprintf("exec fence outage counters unavailable: %v", err))
		return w.inner.WriteStatus(ctx, copy)
	}
	var denied, audit, lost uint64
	for _, totals := range snapshot.PerCgroup {
		denied += totals.OutageDenied
		audit += totals.OutageAudit
		lost += totals.OutageLost
	}
	if denied != 0 || audit != 0 || lost != 0 {
		setExecFenceDegraded(status, "AgentOutageExecs", fmt.Sprintf("retained exec-fence outage totals: %d denied, %d Audit unevaluated, %d lost observations", denied, audit, lost))
	}
	return w.inner.WriteStatus(ctx, copy)
}

func setExecFenceDegraded(status *api.NodeStatus, reason, message string) {
	condition := metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue,
		Reason: reason, Message: message, ObservedGeneration: status.ObservedGeneration, LastTransitionTime: status.LastReported}
	for i, current := range status.Conditions {
		if current.Type != condition.Type {
			continue
		}
		if current.Status == metav1.ConditionTrue {
			reasons := strings.Split(current.Reason, ",")
			if !slices.Contains(reasons, reason) {
				reasons = append(reasons, reason)
			}
			condition.Reason = strings.Join(reasons, ",")
			if current.Message != "" {
				condition.Message = current.Message + "; " + message
			}
			condition.LastTransitionTime = current.LastTransitionTime
		}
		status.Truncated = sandboxpolicy.BoundCondition(&condition) || status.Truncated
		status.Conditions[i] = condition
		return
	}
	status.Truncated = sandboxpolicy.BoundCondition(&condition) || status.Truncated
	status.Conditions = append(status.Conditions, condition)
}
