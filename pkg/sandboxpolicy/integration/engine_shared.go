package integration

import (
	"context"

	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// sharedHealth is the node health surface of the shared engine.
type sharedHealth interface {
	Health() igbackend.SharedNodeHealth
}

// engineStatusWriter folds the shared node's health into the status of every
// policy with exec rules (igbackend.ApplySharedNodeHealth: a node that is not
// Ready makes Ready False, Degraded is merged, D2). Other policies' writes,
// and every write of other engines, are unchanged.
func engineStatusWriter(engine igbackend.FullEngine, w sandboxpolicy.StatusWriter) sandboxpolicy.StatusWriter {
	if health, ok := engine.(sharedHealth); ok {
		return sharedHealthWriter{inner: w, health: health}
	}
	return w
}

type sharedHealthWriter struct {
	inner  sandboxpolicy.StatusWriter
	health sharedHealth
}

func (w sharedHealthWriter) WriteStatus(ctx context.Context, report *api.SandboxPolicyNodeStatus) error {
	if report == nil || report.Status == nil {
		return w.inner.WriteStatus(ctx, report)
	}
	// The shared engine enforces exec only: a policy without exec rules
	// keeps its own Ready and Degraded. Unknown counts as exec.
	if hasExec, known := sandboxpolicy.PolicyExecFrom(ctx); known && !hasExec {
		return w.inner.WriteStatus(ctx, report)
	}
	copy := report.DeepCopy()
	igbackend.ApplySharedNodeHealth(copy.Status, w.health.Health(), copy.Status.ObservedGeneration, copy.Status.LastReported)
	return w.inner.WriteStatus(ctx, copy)
}
