package igbackend

import (
	"context"
	"fmt"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// NetworkTier is how the network gadget attaches its programs.
type NetworkTier string

const (
	// NetworkTierCgroup: cgroup/connect4|6 and cgroup/sendmsg4|6 at the host
	// cgroup root. Needs an IG that attaches cgroup sock_addr programs.
	NetworkTierCgroup NetworkTier = "cgroup"
	// NetworkTierLSM: lsm/socket_connect and lsm/socket_sendmsg. Needs an
	// active BPF LSM.
	NetworkTierLSM NetworkTier = "lsm"
)

// SelectNetworkTier picks the cgroup tier when cgroupAttach reports support
// (nil error), else the LSM tier when BPF LSM is active, else returns an
// EnforcementUnavailableError. A nil cgroupAttach means the cgroup tier is not
// available in this build.
func SelectNetworkTier(hostRoot string, cgroupAttach func() error) (NetworkTier, error) {
	if cgroupAttach != nil && cgroupAttach() == nil {
		return NetworkTierCgroup, nil
	}
	if err := checkBPFLSM(hostRoot, sandboxpolicy.SectionNetwork); err != nil {
		return "", err
	}
	return NetworkTierLSM, nil
}

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
