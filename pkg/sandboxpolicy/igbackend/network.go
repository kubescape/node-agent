package igbackend

import (
	"context"
	"fmt"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// NetworkEngine starts one node-wide enforce_network instance. Start returns
// only after native readiness, or after failed-candidate cleanup.
type NetworkEngine interface {
	Start(ctx context.Context, id string, config netruntime.Config) (NodeInstance, error)
}

// NetworkBackend owns ONE enforce_network instance per node (see nodeOwner).
// A slot is one combination of network policies.
type NetworkBackend struct {
	nodeOwner[netpolicy.Compiled]
}

var (
	_ sandboxpolicy.Backend            = (*NetworkBackend)(nil)
	_ sandboxpolicy.ProtectionAttester = (*NetworkBackend)(nil)
	_ sandboxpolicy.SlotPreparer       = (*NetworkBackend)(nil)
	_ sandboxpolicy.PreparedClearer    = (*NetworkBackend)(nil)
	_ sandboxpolicy.PodBinder          = (*NetworkBackend)(nil)
)

// NewNetwork creates the node backend. validator verifies the live container
// identity before a bind and holds it while bound; nil skips the check (tests).
func NewNetwork(engine NetworkEngine, validator Validator, prefix string) (*NetworkBackend, error) {
	if engine == nil {
		return nil, fmt.Errorf("network engine is required")
	}
	section := nodeSection[netpolicy.Compiled]{
		name:        sandboxpolicy.SectionNetwork,
		combination: NetworkCombination,
		compile: func(generation uint64, slots [][]sandboxpolicy.CompiledPolicy) (netpolicy.Compiled, error) {
			docs := make([][]netpolicy.Document, len(slots))
			for i, policies := range slots {
				for _, p := range policies {
					doc := p.Network.Egress
					doc.Name = p.Identity.Namespace + "/" + p.Identity.Name
					docs[i] = append(docs[i], doc)
				}
			}
			return netpolicy.CompileSlots(docs, generation)
		},
		start: func(ctx context.Context, id string, compiled netpolicy.Compiled, bindings []enforcement.Binding) (NodeInstance, error) {
			return engine.Start(ctx, id, netruntime.Config{Policy: compiled, InitialBindings: bindings})
		},
		// As privilege: the first pod of a network policy after node-agent
		// starts must find the gadget loaded, because its first connect is
		// judged at the pod cgroup.
		startEmpty: true,
		slots:      netpolicy.KernelMaxSlots,
	}
	return &NetworkBackend{newNodeOwner(section, validator, prefix)}, nil
}

// NetworkCombination returns the network policies of a plan, sorted, and their
// key. Only the gadget document is part of the key.
func NetworkCombination(plan sandboxpolicy.Plan) (string, []sandboxpolicy.CompiledPolicy) {
	var policies []sandboxpolicy.CompiledPolicy
	for _, p := range plan.Policies {
		if p.Network != nil {
			policies = append(policies, p)
		}
	}
	return combinationKey(policies, func(p sandboxpolicy.CompiledPolicy) any { return p.Network.Egress })
}
