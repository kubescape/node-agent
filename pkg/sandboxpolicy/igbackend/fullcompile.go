package igbackend

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// CompileFull preserves the complete resolved exec vocabulary and policy-local
// identities. It prepares immutable data only: it neither attests kernel facts
// nor authorizes role bootstrap, image evidence or native publication. The
// interim path-only Compile/Backend remains unchanged until its persistent owner
// is available. activatedRoleEpochs is the persistent owner's SUCCESSFUL UID
// activation catalogue; nil is appropriate only for a fresh owner, not reload.
// The matching expanded IG module is required to build this bridge.
func CompileFull(binding sandboxpolicy.Binding, plan sandboxpolicy.Plan, generation uint64, activatedRoleEpochs map[string]uint64) (*fullpolicy.KernelProgram, error) {
	if plan.Revision == "" || binding.ContainerName == "" {
		return nil, fmt.Errorf("full exec requires plan revision and exact container name")
	}
	policies := make([]fullpolicy.Policy, 0, len(plan.Policies))
	for _, p := range plan.Policies {
		if p.Identity.UID == "" || p.Revision == "" {
			return nil, fmt.Errorf("full exec requires immutable policy UID and revision")
		}
		policy := fullpolicy.Policy{ID: string(p.Identity.UID), Revision: p.Revision, Mode: fullpolicy.Mode(p.Mode), RootRole: p.RootRole, Default: fullpolicy.Action(p.Exec.Default)}
		for _, r := range p.Exec.Rules {
			if len(r.Target.PathClass) != 0 {
				return nil, fmt.Errorf("rule %q has unresolved path classes", r.Name)
			}
			rule := fullpolicy.Rule{Name: r.Name, Origin: r.Origin, Action: fullpolicy.Action(r.Action), Mode: fullpolicy.Mode(r.Mode), Target: fullpolicy.Target{Path: r.Target.Path, FromImage: r.Target.FromImage, FSType: r.Target.FSType, SetRole: r.Target.SetRole}}
			if a := r.Actor; a != nil {
				rule.Actor = fullpolicy.Actor{Path: a.Path, FromImage: a.FromImage, Role: a.Role, UID: a.UID, Container: a.Container}
				if a.Ancestor != nil {
					rule.Actor.Ancestor = &fullpolicy.Ancestor{Path: a.Ancestor.Path, Depth: a.Ancestor.Depth}
				}
			}
			if a := r.Target.Argv; a != nil {
				rule.Target.Argv = &fullpolicy.Argv{Contains: a.Contains, Prefix: a.Prefix, StdinIsPipe: a.StdinIsPipe}
			}
			policy.Rules = append(policy.Rules, rule)
		}
		policies = append(policies, policy)
	}
	// CompileKernel validates and deep-copies all caller-owned slices and pointers;
	// no API object survives as mutable kernel matching input.
	return fullpolicy.CompileKernelWithRoleEpochs(policies, generation, binding.ContainerName, activatedRoleEpochs)
}
