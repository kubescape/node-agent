//go:build sandbox_shared_qualification

package integration

import (
	"context"
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"oras.land/oras-go/v2"
)

// newFullEngine runs the G020 shared node engine (never Ready) on the
// candidate image sandboxPolicyImage names in qualification builds. It
// requires sandboxPolicyEngine "shared"; any other engine is refused
// (fail-closed).
func newFullEngine(_ context.Context, r runtime.Runtime, _ operators.DataOperator, store oras.ReadOnlyTarget, options ServiceOptions, report func(error)) (igbackend.FullEngine, error) {
	q, err := config.SandboxSharedQualificationFrom(options.Engine)
	if err != nil {
		return nil, err
	}
	if q.Engine != config.SandboxPolicyEngineShared {
		return nil, fmt.Errorf("sandboxPolicyEngine %q: a sandbox_shared_qualification build requires sandboxPolicyEngine %q", q.Engine, config.SandboxPolicyEngineShared)
	}
	profile, err := igbackend.LoadSharedProfile(q.ProfileFile)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(options.ImageName) == "" || strings.TrimSpace(options.ImageName) != options.ImageName {
		return nil, fmt.Errorf("sandboxPolicyImage %q: a sandbox_shared_qualification build requires the candidate image name, without surrounding whitespace", options.ImageName)
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
