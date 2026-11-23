package igbackend

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// CompileFull preserves the complete resolved exec vocabulary and policy-local
// identities. It prepares immutable data only: it neither attests kernel facts
// nor authorizes role bootstrap, image evidence or native publication. The
// interim path-only Compile/Backend remains unchanged until its persistent owner
// is available. activatedRoleEpochs is the persistent owner's SUCCESSFUL UID
// activation catalogue; nil is appropriate only for a fresh owner, not reload.
// The matching expanded IG module is required to build this bridge.
func CompileFull(binding sandboxpolicy.Binding, plan sandboxpolicy.Plan, generation uint64, activatedRoleEpochs map[string]uint64) (*fullpolicy.KernelProgram, error) {
	policies, err := fullPolicies(binding, plan)
	if err != nil {
		return nil, err
	}
	// CompileKernel validates and deep-copies all caller-owned slices and pointers;
	// no API object survives as mutable kernel matching input.
	return fullpolicy.CompileKernelWithRoleEpochs(policies, generation, binding.ContainerName, activatedRoleEpochs)
}

// fullPolicies converts a resolved plan into the IG policy vocabulary that
// CompileFull compiles, refusing inputs the native ABI cannot express.
func fullPolicies(binding sandboxpolicy.Binding, plan sandboxpolicy.Plan) ([]fullpolicy.Policy, error) {
	if plan.Revision == "" || binding.ContainerName == "" {
		return nil, fmt.Errorf("full exec requires plan revision and exact container name")
	}
	policies := make([]fullpolicy.Policy, 0, len(plan.Policies))
	for _, p := range plan.Policies {
		if p.Identity.UID == "" || p.Revision == "" {
			return nil, fmt.Errorf("full exec requires immutable policy UID and revision")
		}
		if p.Exec.DefaultMode != "" {
			return nil, fmt.Errorf("exec defaultMode requires native IG ABI support")
		}
		policy := fullpolicy.Policy{ID: string(p.Identity.UID), Revision: p.Revision, Mode: fullpolicy.Mode(p.Mode), RootRole: p.RootRole, Default: fullpolicy.Action(p.Exec.Default)}
		for _, r := range p.Exec.Rules {
			if r.Except != nil {
				return nil, fmt.Errorf("rule %q exceptions require native IG ABI support", r.Name)
			}
			if len(r.Target.PathClass) != 0 {
				return nil, fmt.Errorf("rule %q has unresolved path classes", r.Name)
			}
			rule := fullpolicy.Rule{Name: r.Name, Origin: originValue(r.Origin), Action: fullpolicy.Action(r.Action), Mode: fullpolicy.Mode(r.Mode), Target: fullpolicy.Target{Path: r.Target.Path, FromImage: r.Target.FromImage, FSType: r.Target.FSType, SetRole: r.Target.SetRole}}
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
		if mode, ok := loaderDenyMode(p.Mode, p.Exec); ok {
			policy.Rules = append(policy.Rules, loaderDenyRule(policy.Rules, mode))
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

// loaderOrigin is the origin of the exec deny rule that node-agent adds for the
// dynamic loaders (see needsLoaderDeny).
const loaderOrigin = "node-agent/loader"

// loaderRuleName is the base name of the added loader rule; a free "~N" suffix
// is appended when an authored exec rule already uses it.
const loaderRuleName = "node-agent-loader-deny"

// loaderPath matches the glibc and musl dynamic loaders by file name:
// ld-linux-x86-64.so.2, ld-linux-aarch64.so.1, the ld-musl-<arch>.so.1 files,
// and ld-2.NN.so, the real file behind the ld-linux symlink before glibc 2.34
// (the exec hook judges the resolved path). It does not match ld64.so.1
// (s390x) or ld64.so.2 (ppc64le); that is fine for amd64 and arm64, and must
// change when those architectures are supported. It is a glob over every
// directory because the loader's directory differs per distribution. It costs
// about 20 of the 256 cells of a shared-engine policy object; the four exact
// loader names cost 117.
const loaderPath = "/**/ld-*.so*"

// loaderDenyMode reports whether a node-agent loader deny rule is added to an
// exec section, and its mode. It is added when the section denies by path
// (sandboxpolicy.ExecDeniesByPath) and no authored allow rule names a loader
// on purpose (sandboxpolicy.LoaderAllowRule): "ld.so <program>" execs only the
// loader, so without it a path deny is bypassed through a loader that an image
// allow admits. The mode is the strongest mode of those denies, so the loader
// is never denied more or less strongly than the denies it protects.
func loaderDenyMode(policyMode api.PolicyMode, exec api.ExecSection) (fullpolicy.Mode, bool) {
	if !sandboxpolicy.ExecDeniesByPath(exec) {
		return "", false
	}
	if _, _, ok := sandboxpolicy.LoaderAllowRule(exec); ok {
		return "", false
	}
	enforce := exec.Default == api.ActionDeny && policyMode == api.ModeEnforce
	for _, r := range exec.Rules {
		if r.Action == api.ActionDeny && len(r.Target.Path) != 0 {
			enforce = enforce || r.Mode == api.RuleEnforce || (r.Mode == "" && policyMode == api.ModeEnforce)
		}
	}
	if enforce {
		return fullpolicy.Enforce, true
	}
	return fullpolicy.Audit, true
}

// loaderDenyRule is the loader deny rule, named with a name no authored rule
// of the policy uses.
func loaderDenyRule(rules []fullpolicy.Rule, mode fullpolicy.Mode) fullpolicy.Rule {
	used := make(map[string]bool, len(rules))
	for _, r := range rules {
		used[r.Name] = true
	}
	name := loaderRuleName
	for i := 1; used[name]; i++ {
		name = fmt.Sprintf("%s~%d", loaderRuleName, i)
	}
	return fullpolicy.Rule{Name: name, Origin: loaderOrigin, OriginPresent: true, Action: fullpolicy.Deny, Mode: mode, Target: fullpolicy.Target{Path: []string{loaderPath}}}
}

func originValue(origin *string) string {
	if origin == nil {
		return ""
	}
	return *origin
}
