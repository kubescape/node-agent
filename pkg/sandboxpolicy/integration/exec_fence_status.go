// Copyright 2026 The Kubescape authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type execFenceStatus interface {
	Refusal() error
	Snapshot() (restartfence.Snapshot, error)
}

type execFenceStatusCache struct {
	mu          sync.Mutex
	active      bool
	populated   bool
	refusal     error
	reclaimErr  error
	snapshotErr error
	denied      uint64
	audit       uint64
	lost        uint64
}

func (c *execFenceStatusCache) Begin() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = true
	c.populated = false
}

func (c *execFenceStatusCache) End() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = false
	c.populated = false
	c.refusal = nil
	c.reclaimErr = nil
	c.snapshotErr = nil
	c.denied, c.audit, c.lost = 0, 0, 0
}

type execFenceStatusWriter struct {
	inner sandboxpolicy.StatusWriter
	fence execFenceStatus
	cache *execFenceStatusCache
}

func (w execFenceStatusWriter) readSummary() (refusal, reclaimErr, snapshotErr error, denied, audit, lost uint64) {
	if w.cache != nil {
		w.cache.mu.Lock()
		if w.cache.active && w.cache.populated {
			refusal, reclaimErr, snapshotErr = w.cache.refusal, w.cache.reclaimErr, w.cache.snapshotErr
			denied, audit, lost = w.cache.denied, w.cache.audit, w.cache.lost
			w.cache.mu.Unlock()
			return
		}
		w.cache.mu.Unlock()
	}
	refusal = w.fence.Refusal()
	if refusal == nil {
		if reclaimer, ok := w.fence.(interface{ ReclamationError() error }); ok {
			reclaimErr = reclaimer.ReclamationError()
		}
		var snapshot restartfence.Snapshot
		snapshot, snapshotErr = w.fence.Snapshot()
		if snapshotErr == nil {
			for _, totals := range snapshot.PerCgroup {
				denied += totals.OutageDenied
				audit += totals.OutageAudit
				lost += totals.OutageLost
			}
		}
	}
	if w.cache != nil {
		w.cache.mu.Lock()
		if w.cache.active {
			w.cache.populated = true
			w.cache.refusal = refusal
			w.cache.reclaimErr = reclaimErr
			w.cache.snapshotErr = snapshotErr
			w.cache.denied = denied
			w.cache.audit = audit
			w.cache.lost = lost
		}
		w.cache.mu.Unlock()
	}
	return
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
	refusal, reclaimErr, snapshotErr, denied, audit, lost := w.readSummary()
	if refusal != nil {
		for i, c := range status.Conditions {
			if c.Type != "Ready" || c.Reason == sandboxpolicy.AgentStoppingReason || c.Reason == sandboxpolicy.AgentStoppingUnconfirmedReason {
				continue
			}
			c.Status = metav1.ConditionFalse
			c.Reason = "ExecFenceAdoptionRefused"
			c.Message = fmt.Sprintf("exec fence adoption refused; product enforcement cannot be reported: %v", refusal)
			status.Truncated = sandboxpolicy.BoundCondition(&c) || status.Truncated
			status.Conditions[i] = c
		}
		status.AppliedGeneration = 0
		return w.inner.WriteStatus(ctx, copy)
	}
	if reclaimErr != nil {
		setExecFenceDegraded(status, "ExecFenceGCUnavailable", fmt.Sprintf("exec fence cgroup exit proof unavailable; retaining affected rows: %v", reclaimErr))
	}
	if snapshotErr != nil {
		setExecFenceDegraded(status, "AgentOutageExecsUnavailable", fmt.Sprintf("exec fence outage counters unavailable: %v", snapshotErr))
		return w.inner.WriteStatus(ctx, copy)
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
