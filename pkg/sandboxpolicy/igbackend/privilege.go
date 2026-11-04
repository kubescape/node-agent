package igbackend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

// PrivilegeEngine starts one node-wide enforce_privilege instance. Start returns
// only after native readiness, or after failed-candidate cleanup.
type PrivilegeEngine interface {
	Start(ctx context.Context, id string, config privruntime.Config) (PrivilegeInstance, error)
}

// PrivilegeInstance is a running enforce_privilege instance. SlotHealth fails
// when the instance counted a tracking fault in the slot: a task of an
// enforcing slot may be untracked, or a fork was refused.
type PrivilegeInstance = NodeInstance

// PrivilegeStats counts how container binds found their policy slot.
type PrivilegeStats = NodeStats

// PrivilegeBackend owns ONE enforce_privilege instance per node (see
// nodeOwner). A slot is one combination of privilege policies.
type PrivilegeBackend struct {
	nodeOwner[privpolicy.Compiled]
}

var (
	_ sandboxpolicy.Backend            = (*PrivilegeBackend)(nil)
	_ sandboxpolicy.ProtectionAttester = (*PrivilegeBackend)(nil)
	_ sandboxpolicy.SlotPreparer       = (*PrivilegeBackend)(nil)
	_ sandboxpolicy.PodBinder          = (*PrivilegeBackend)(nil)
)

// NewPrivilege creates the node backend. validator verifies the live container
// identity before a bind and holds it while bound; nil skips the check (tests).
func NewPrivilege(engine PrivilegeEngine, validator Validator, prefix string) (*PrivilegeBackend, error) {
	if engine == nil {
		return nil, fmt.Errorf("privilege engine is required")
	}
	section := nodeSection[privpolicy.Compiled]{
		name:        sandboxpolicy.SectionPrivilege,
		combination: Combination,
		compile: func(generation uint64, slots [][]sandboxpolicy.CompiledPolicy) (privpolicy.Compiled, error) {
			docs := make([][]privpolicy.Document, len(slots))
			for i, policies := range slots {
				for _, p := range policies {
					doc, err := sandboxpolicy.PrivilegeDocument(p.Identity.Namespace+"/"+p.Identity.Name, p.Mode, *p.Privilege)
					if err != nil {
						return privpolicy.Compiled{}, err
					}
					docs[i] = append(docs[i], doc)
				}
			}
			return privpolicy.CompileSlots(docs, generation)
		},
		start: func(ctx context.Context, id string, compiled privpolicy.Compiled, bindings []enforcement.Binding) (NodeInstance, error) {
			return engine.Start(ctx, id, privruntime.Config{Policy: compiled, InitialBindings: bindings})
		},
		// The first container of a privilege policy must find the gadget
		// loaded: its first exec is judged at the pod cgroup.
		startEmpty: true,
	}
	return &PrivilegeBackend{newNodeOwner(section, validator, prefix)}, nil
}

// Combination returns the privilege policies of a plan, sorted, and their key.
func Combination(plan sandboxpolicy.Plan) (string, []sandboxpolicy.CompiledPolicy) {
	var policies []sandboxpolicy.CompiledPolicy
	for _, p := range plan.Policies {
		if p.Privilege != nil {
			policies = append(policies, p)
		}
	}
	return combinationKey(policies, func(p sandboxpolicy.CompiledPolicy) any { return p.Privilege })
}

// combinationKey sorts the policies of one section and digests their identity,
// mode and section content.
func combinationKey(policies []sandboxpolicy.CompiledPolicy, content func(sandboxpolicy.CompiledPolicy) any) (string, []sandboxpolicy.CompiledPolicy) {
	sort.Slice(policies, func(i, j int) bool { return policies[i].Identity.UID < policies[j].Identity.UID })
	type part struct {
		UID, Name, Mode string
		Section         any
	}
	parts := make([]part, len(policies))
	for i, p := range policies {
		parts[i] = part{string(p.Identity.UID), p.Identity.Namespace + "/" + p.Identity.Name, string(p.Mode), content(p)}
	}
	data, _ := json.Marshal(parts) // concrete JSON-serializable API structs
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), policies
}

// BindPods binds pod cgroups to their privilege slot (see nodeOwner.bindPods).
// Only the privilege section binds pod cgroups.
func (b *PrivilegeBackend) BindPods(ctx context.Context, pods []sandboxpolicy.PodBinding) error {
	return b.bindPods(ctx, pods)
}
