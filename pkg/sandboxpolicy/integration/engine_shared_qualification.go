//go:build sandbox_shared_qualification

package integration

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"oras.land/oras-go/v2"
)

// newFullEngine selects the engine in qualification builds: the per-binding
// engine unless sandboxPolicyEngine is "shared" (G020 shared node engine,
// never Ready). Only the per-binding engine takes the legacy per-cgroup Owner
// budget: the shared engine attaches no per-cgroup Owners.
func newFullEngine(_ context.Context, r runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, options ServiceOptions, report func(error)) (igbackend.FullEngine, error) {
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
	profile, err := igbackend.LoadSharedProfile(q.ProfileFile)
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
