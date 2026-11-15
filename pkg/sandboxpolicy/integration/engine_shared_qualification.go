//go:build sandbox_shared_qualification

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"oras.land/oras-go/v2"
)

// newFullEngine selects the engine in qualification builds: the per-binding
// engine unless sandboxPolicyEngine is "shared" (G020 shared node engine,
// never Ready). Only the per-binding engine takes the legacy per-cgroup Owner
// budget: the shared engine attaches no per-cgroup Owners.
func newFullEngine(r runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, options ServiceOptions, report func(error)) (igbackend.FullEngine, error) {
	q, err := config.SandboxSharedQualificationFrom(options.Engine)
	if err != nil {
		return nil, err
	}
	if q.Engine != config.SandboxPolicyEngineShared {
		budget, err := newLegacyBudget(options.MaxOwners)
		if err != nil {
			return nil, err
		}
		return igbackend.NewNativeFullEngine(r, kube, store, options.ImageName, options.ControlRoot, budget, report)
	}
	profile, err := loadSharedProfile(q.ProfileFile)
	if err != nil {
		return nil, err
	}
	engine, err := igbackend.NewSharedQualificationEngine(r, sharedEngineConfig(q, profile, store, options), report)
	if err != nil {
		return nil, err
	}
	return engine, nil
}

func sharedEngineConfig(q config.SandboxSharedQualification, profile fullruntime.SharedProfile, store oras.ReadOnlyTarget, options ServiceOptions) igbackend.SharedEngineConfig {
	return igbackend.SharedEngineConfig{Profile: profile, Image: options.ImageName, Store: store, ContainerdAddress: options.ContainerdSocket, ImageProcRoot: q.ImageProcRoot, ImageHostRoot: q.ImageHostRoot}
}

// loadSharedProfile reads the exact geometry the candidate image was built with.
func loadSharedProfile(path string) (fullruntime.SharedProfile, error) {
	var profile fullruntime.SharedProfile
	data, err := os.ReadFile(path)
	if err != nil {
		return profile, fmt.Errorf("shared profile: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return profile, fmt.Errorf("shared profile %s: %w", path, err)
	}
	if _, err := profile.Validate(); err != nil {
		return profile, fmt.Errorf("shared profile %s: %w", path, err)
	}
	return profile, nil
}

// sharedHealth is the node health surface of the shared engine.
type sharedHealth interface {
	Health() igbackend.SharedNodeHealth
}

// engineStatusWriter folds the shared node's health into every status the
// controller writes (Ready stays False, Degraded per D2); other engines'
// writes are unchanged.
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
	copy := report.DeepCopy()
	igbackend.ApplySharedNodeHealth(copy.Status, w.health.Health(), copy.Status.ObservedGeneration, copy.Status.LastReported)
	return w.inner.WriteStatus(ctx, copy)
}
