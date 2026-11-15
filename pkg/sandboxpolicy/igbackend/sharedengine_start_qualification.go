//go:build sandbox_shared_qualification

package igbackend

// G020 shared node engine, qualification start (QUALIFICATION ONLY): the IG
// qualification seam. The engine never reports Ready.
//
// Build: -tags sandbox_shared_qualification,enforce_exec_shared_qualification
// (the IG tag enables its qualification StartNode path; see
// sharedengine_qualification_guard.go).

import (
	"context"
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

// NewSharedQualificationEngine borrows the initialized runtime; the node
// starts on the first Start through a manager of that runtime.
func NewSharedQualificationEngine(rt runtime.Runtime, config SharedEngineConfig, onError func(error)) (*SharedEngine, error) {
	if fullruntime.SharedNodeAPIVersion != SharedEngineAPIVersion {
		return nil, fmt.Errorf("IG shared node API version %d, engine requires %d", fullruntime.SharedNodeAPIVersion, SharedEngineAPIVersion)
	}
	if rt == nil || config.Store == nil || config.Image == "" {
		return nil, fmt.Errorf("runtime and trusted shared candidate image/store are required")
	}
	if _, err := config.Profile.Validate(); err != nil {
		return nil, err
	}
	manager, err := instancemanager.New(rt)
	if err != nil {
		return nil, err
	}
	e := newSharedEngine(sharedQualification, nil, onError)
	e.start = func(ctx context.Context) (sharedNode, error) {
		return e.startNode(ctx, manager, config, qualificationHost)
	}
	return e, nil
}

func qualificationHost(ctx context.Context, run func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error)) context.Context {
	return fullruntime.WithSharedNodeQualification(ctx, fullruntime.SharedNodeQualification{Run: run})
}
