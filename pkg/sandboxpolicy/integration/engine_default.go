//go:build !sandbox_shared_qualification

package integration

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"oras.land/oras-go/v2"
)

// newFullEngine is the product engine: one persistent native owner per binding.
func newFullEngine(r runtime.Runtime, kube operators.DataOperator, store oras.ReadOnlyTarget, options ServiceOptions, report func(error)) (igbackend.FullEngine, error) {
	// Never run a configured shared engine's image as per-binding owners.
	if options.Engine.Engine != "" && options.Engine.Engine != "full" {
		return nil, fmt.Errorf("sandboxPolicyEngine %q requires a sandbox_shared_qualification build", options.Engine.Engine)
	}
	budget, err := newLegacyBudget(options.MaxOwners)
	if err != nil {
		return nil, err
	}
	return igbackend.NewNativeFullEngine(r, kube, store, options.ImageName, options.ControlRoot, budget, report)
}

// engineStatusWriter is w: the product engine adds no node health.
func engineStatusWriter(_ igbackend.FullEngine, w sandboxpolicy.StatusWriter) sandboxpolicy.StatusWriter {
	return w
}
