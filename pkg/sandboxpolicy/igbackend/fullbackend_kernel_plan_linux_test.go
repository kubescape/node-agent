//go:build linux

package igbackend

import (
	"fmt"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"github.com/stretchr/testify/require"
	"testing"
)

func fullBackendKernelPlan(revision, rootRole string, denied, audited int, container string) sandboxpolicy.Plan {
	yes := true
	actor := func(role string) *api.Actor {
		return &api.Actor{Path: []string{"/probe/init", "/probe/role"}, FromImage: &yes, Ancestor: &api.Ancestor{Path: []string{"/probe/init", "/probe/role"}, Depth: 2}, Role: []string{role}, UID: []int64{0}, Container: []string{container}}
	}
	target := func(paths []string) api.ExecTarget {
		return api.ExecTarget{PathTarget: api.PathTarget{Path: paths, FromImage: &yes, FSType: []string{"overlay"}}, Argv: &api.ArgvPredicate{Contains: []string{"--token=ok"}, Prefix: []string{"--token="}, StdinIsPipe: &yes}}
	}
	paths := make([]string, 13)
	for i := range paths {
		paths[i] = fmt.Sprintf("/probe/target-%d", i)
	}
	stage := target([]string{"/probe/role"})
	stage.SetRole = "worker"
	return sandboxpolicy.Plan{Revision: revision, Policies: []sandboxpolicy.CompiledPolicy{{Identity: sandboxpolicy.PolicyIdentity{Kind: "SandboxPolicy", Name: "fixture", UID: "fixture-policy-uid"}, Revision: "policy-" + revision, Mode: "enforce", RootRole: rootRole, Exec: api.ExecSection{Default: api.ActionDeny, Rules: []api.ExecRule{
		{Rule: api.Rule{Name: "root-paths", Origin: "fixture/full-predicates", Action: api.ActionAllow, Actor: actor("agent")}, Target: target(paths)},
		{Rule: api.Rule{Name: "deny-control", Action: api.ActionDeny}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{fmt.Sprintf("/probe/target-%d", denied)}}}},
		{Rule: api.Rule{Name: "audit-control", Action: api.ActionDeny, Mode: api.RuleAudit}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{fmt.Sprintf("/probe/target-%d", audited)}}}},
		{Rule: api.Rule{Name: "root-role-control", Action: api.ActionDeny, Actor: &api.Actor{Role: []string{"agent"}}}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/probe/target-12"}}}},
		{Rule: api.Rule{Name: "grant-worker", Action: api.ActionAllow, Actor: actor("agent")}, Target: stage},
		{Rule: api.Rule{Name: "inherited-worker", Action: api.ActionAllow, Actor: actor("worker")}, Target: target([]string{"/probe/target-12"})},
	}}}}}
}

func TestFullBackendKernelFixturePlan(t *testing.T) {
	for _, revision := range []string{"plan-1", "plan-2"} {
		p := fullBackendKernelPlan(revision, "agent", 0, 1, "app")
		program, err := CompileFull(sandboxpolicy.Binding{ContainerName: "app"}, p, 1, nil)
		require.NoError(t, err)
		rule, err := fullpolicy.Decode[fullpolicy.KernelRule](program.Entries[fullpolicy.KernelRuleBase])
		require.NoError(t, err)
		require.Equal(t, uint32(13), rule.TargetPath.Count)
	}
}
