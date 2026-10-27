package igbackend

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

func fullPlan() sandboxpolicy.Plan {
	yes, no := true, false
	return sandboxpolicy.Plan{Revision: "combined-revision", Policies: []sandboxpolicy.CompiledPolicy{
		{Identity: sandboxpolicy.PolicyIdentity{UID: "uid-one"}, Revision: "revision-one", Mode: "enforce", RootRole: "root", Exec: api.ExecSection{Rules: []api.ExecRule{{Rule: api.Rule{Name: "full-rule", Origin: "imported/profile", Action: "allow", Mode: "audit", Actor: &api.Actor{Path: []string{"/actor/*"}, FromImage: &no, Ancestor: &api.Ancestor{Path: []string{"/ancestor"}, Depth: 4}, Role: []string{"root", "worker"}, UID: []int64{0, 1000}, Container: []string{"app", "sidecar"}}}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/bin/*"}, FromImage: &yes, FSType: []string{"tmpfs", "memfd", "deleted", "overlay"}}, Argv: &api.ArgvPredicate{Contains: []string{"needle", "other"}, Prefix: []string{"/bin/", "--"}, StdinIsPipe: &no}, SetRole: "worker"}}}}},
		{Identity: sandboxpolicy.PolicyIdentity{UID: "uid-two"}, Revision: "revision-two", Mode: "audit", RootRole: "other-root", Exec: api.ExecSection{Default: "deny"}},
	}}
}
func TestCompileFullPreservesResolvedVocabulary(t *testing.T) {
	plan := fullPlan()
	got, err := CompileFull(sandboxpolicy.Binding{ContainerName: "app"}, plan, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := fullpolicy.Decode[fullpolicy.KernelHeader](got.Entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if h.Generation != 7 || h.PolicyCount != 2 || h.RuleCount != 1 {
		t.Fatalf("header: %+v", h)
	}
	r, err := fullpolicy.Decode[fullpolicy.KernelRule](got.Entries[h.RuleBase])
	if err != nil {
		t.Fatal(err)
	}
	if r.Mode != 1 || r.Deny != 0 || r.ActorImage != 0 || r.TargetImage != 1 || r.Stdin != 0 || r.AncestorDepth != 4 || r.SetRole == 0 {
		t.Fatalf("scalars: %+v", r)
	}
	counts := []uint32{r.ActorPath.Count, r.TargetPath.Count, r.AncestorPath.Count, r.ActorRole.Count, r.UID.Count, r.Container.Count, r.FSType.Count, r.ArgContains.Count, r.ArgPrefix.Count}
	if !reflect.DeepEqual(counts, []uint32{1, 1, 1, 2, 2, 2, 4, 2, 2}) {
		t.Fatalf("lost predicates: %v", counts)
	}
	for i, want := range []fullpolicy.KernelPolicy{{Default: 0, Mode: 2}, {Default: 2, Mode: 1}} {
		p, err := fullpolicy.Decode[fullpolicy.KernelPolicy](got.Entries[fullpolicy.KernelPolicyBase+i])
		if err != nil {
			t.Fatal(err)
		}
		if p.UID == 0 || p.RootRole == 0 || p.Default != want.Default || p.Mode != want.Mode {
			t.Fatalf("policy%d: %+v", i, p)
		}
	}
	if len(got.Rules) != 1 || got.Rules[0].PolicyID != "uid-one" || got.Rules[0].Revision != "revision-one" || got.Rules[0].Origin != "imported/profile" {
		t.Fatalf("provenance: %+v", got.Rules)
	}
	// API mutation after compilation cannot alter any frozen-map bytes or names.
	before := append([]fullpolicy.Blob(nil), got.Entries...)
	plan.Policies[0].Exec.Rules[0].Actor.Path[0] = "/mutated"
	*plan.Policies[0].Exec.Rules[0].Target.FromImage = false
	if !reflect.DeepEqual(before, got.Entries) {
		t.Fatal("compiled entries alias API")
	}
}
func TestCompileFullBeyondEightPaths(t *testing.T) {
	p := fullPlan()
	p.Policies = p.Policies[:1]
	r := &p.Policies[0].Exec.Rules[0]
	r.Target.Path = nil
	for i := 0; i < 128; i++ {
		r.Target.Path = append(r.Target.Path, fmt.Sprintf("/bin/tool-%d", i))
	}
	got, err := CompileFull(sandboxpolicy.Binding{ContainerName: "app"}, p, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := fullpolicy.Decode[fullpolicy.KernelRule](got.Entries[fullpolicy.KernelRuleBase])
	if err != nil {
		t.Fatal(err)
	}
	if rule.TargetPath.Count != 128 {
		t.Fatalf("truncated paths: %d", rule.TargetPath.Count)
	}
}
func TestCompileFullRefusesUnresolvedOrInvalidCandidates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*sandboxpolicy.Plan)
	}{
		{"revision", func(p *sandboxpolicy.Plan) { p.Revision = "" }},
		{"uid", func(p *sandboxpolicy.Plan) { p.Policies[0].Identity.UID = "" }},
		{"policy-revision", func(p *sandboxpolicy.Plan) { p.Policies[0].Revision = "" }},
		{"duplicate-uid", func(p *sandboxpolicy.Plan) { p.Policies[1].Identity.UID = p.Policies[0].Identity.UID }},
		{"unresolved-class", func(p *sandboxpolicy.Plan) { p.Policies[0].Exec.Rules[0].Target.PathClass = []string{"class"} }},
		{"unknown-mode", func(p *sandboxpolicy.Plan) { p.Policies[0].Mode = "off" }},
		{"unknown-fs", func(p *sandboxpolicy.Plan) { p.Policies[0].Exec.Rules[0].Target.FSType = []string{"guess"} }},
		{"oversized-path", func(p *sandboxpolicy.Plan) {
			p.Policies[0].Exec.Rules[0].Target.Path = []string{"/" + strings.Repeat("x", 256)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fullPlan()
			tc.mutate(&p)
			if got, err := CompileFull(sandboxpolicy.Binding{ContainerName: "app"}, p, 1, nil); err == nil || got != nil {
				t.Fatal("invalid candidate admitted")
			}
		})
	}
	if _, err := CompileFull(sandboxpolicy.Binding{}, fullPlan(), 1, nil); err == nil {
		t.Fatal("missing container name admitted")
	}
	if _, err := CompileFull(sandboxpolicy.Binding{ContainerName: "app"}, fullPlan(), 0, nil); err == nil {
		t.Fatal("zero generation admitted")
	}
}

func TestCompileFullRetainsAcceptedRoleEpochs(t *testing.T) {
	p, err := CompileFull(sandboxpolicy.Binding{ContainerName: "app"}, fullPlan(), 9, map[string]uint64{"uid-one": 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		entry, err := fullpolicy.Decode[fullpolicy.KernelPolicy](p.Entries[fullpolicy.KernelPolicyBase+i])
		if err != nil {
			t.Fatal(err)
		}
		want := uint64(9)
		if p.Identities[entry.UID] == "uid-one" {
			want = 2
		}
		if entry.RootEpoch != want {
			t.Fatalf("UID epoch lost: %+v", entry)
		}
	}
}
