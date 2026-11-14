package integration

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ErrInputsChanged = errors.New("sandbox inputs changed during synchronization")

// readinessWriter makes concurrent discovery/configuration hints part of the
// status barrier. Committed enforcement remains installed, but an incomplete
// snapshot cannot announce Ready while an observed input change awaits replay.
type readinessWriter struct {
	inner              sandboxpolicy.StatusWriter
	observed, snapshot *atomic.Uint64
}

func (w readinessWriter) WriteStatus(ctx context.Context, report *api.SandboxPolicyNodeStatus) error {
	changed := w.observed.Load() != w.snapshot.Load()
	if !changed {
		return w.inner.WriteStatus(ctx, report)
	}
	copy := report.DeepCopy()
	if copy.Status != nil {
		copy.Status.Stale = true
		for i := range copy.Status.Conditions {
			if copy.Status.Conditions[i].Type == "Ready" && copy.Status.Conditions[i].Status == metav1.ConditionTrue {
				copy.Status.Conditions[i].Status = metav1.ConditionFalse
				copy.Status.Conditions[i].Reason = "InputsChanged"
				copy.Status.Conditions[i].Message = "Observed inputs changed during synchronization; replay is pending and newly selected containers may be unprotected"
			}
		}
	}
	return errors.Join(ErrInputsChanged, w.inner.WriteStatus(ctx, copy))
}
