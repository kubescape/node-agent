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
		{Identity: sandboxpolicy.PolicyIdentity{UID: "uid-one"}, Revision: "revision-one", Mode: "enforce", RootRole: "root", Exec: api.ExecSection{Rules: []api.ExecRule{{Rule: api.Rule{Name: "full-rule", Origin: testOrigin("imported/profile"), Action: "allow", Mode: "audit", Actor: &api.Actor{Path: []string{"/actor/*"}, FromImage: &no, Ancestor: &api.Ancestor{Path: []string{"/ancestor"}, Depth: 4}, Role: []string{"root", "worker"}, UID: []int64{0, 1000}, Container: []string{"app", "sidecar"}}}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: []string{"/bin/*"}, FromImage: &yes, FSType: []string{"tmpfs", "memfd", "deleted", "overlay"}}, Argv: &api.ArgvPredicate{Contains: []string{"needle", "other"}, Prefix: []string{"/bin/", "--"}, StdinIsPipe: &no}, SetRole: "worker"}}}}},
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
	// uid-two's deny default adds the loader deny rule after uid-one's rule.
	if h.Generation != 7 || h.PolicyCount != 2 || h.RuleCount != 2 {
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
	if len(got.Rules) != 2 || got.Rules[1].Origin != loaderOrigin || got.Rules[0].PolicyID != "uid-one" || got.Rules[0].Revision != "revision-one" || got.Rules[0].Origin != "imported/profile" {
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

func testOrigin(value string) *string { return &value }

func TestCompileFullRejectsUnsupportedNativeSemantics(t *testing.T) {
	binding := sandboxpolicy.Binding{ContainerName: "app"}
	for _, change := range []func(*sandboxpolicy.Plan){
		func(p *sandboxpolicy.Plan) { p.Policies[0].Exec.DefaultMode = api.RuleAudit },
		func(p *sandboxpolicy.Plan) {
			p.Policies[0].Exec.Rules[0].Except = []api.ExecException{{Target: &api.ExecExceptionTarget{PathTarget: api.PathTarget{Path: []string{"/bin/safe"}}}}}
		},
	} {
		p := fullPlan()
		change(&p)
		if _, err := CompileFull(binding, p, 7, nil); err == nil || !strings.Contains(err.Error(), "native IG ABI") {
			t.Fatalf("unsupported semantic revision accepted: %v", err)
		}
	}
}

func loaderPlan(def api.Action, rules ...api.ExecRule) sandboxpolicy.Plan {
	return sandboxpolicy.Plan{Revision: "loader-revision", Policies: []sandboxpolicy.CompiledPolicy{{Identity: sandboxpolicy.PolicyIdentity{UID: "uid-loader"}, Revision: "r", Mode: "enforce", RootRole: "root", Exec: api.ExecSection{Default: def, Rules: rules}}}}
}

func execRule(name string, action api.Action, paths ...string) api.ExecRule {
	return api.ExecRule{Rule: api.Rule{Name: name, Action: action}, Target: api.ExecTarget{PathTarget: api.PathTarget{Path: paths}}}
}

func loaderRules(t *testing.T, plan sandboxpolicy.Plan) []fullpolicy.Rule {
	t.Helper()
	policies, err := fullPolicies(sandboxpolicy.Binding{ContainerName: "app"}, plan)
	if err != nil {
		t.Fatal(err)
	}
	var out []fullpolicy.Rule
	for _, r := range policies[0].Rules {
		if r.Origin == loaderOrigin {
			out = append(out, r)
		}
	}
	return out
}

func TestFullPoliciesAddsLoaderDenyOnPathDeny(t *testing.T) {
	yes := true
	imageAllow := api.ExecRule{Rule: api.Rule{Name: "image", Action: api.ActionAllow}, Target: api.ExecTarget{PathTarget: api.PathTarget{FromImage: &yes}}}
	for _, tc := range []struct {
		name string
		plan sandboxpolicy.Plan
		want bool
	}{
		{"default deny", loaderPlan(api.ActionDeny, imageAllow), true},
		{"deny rule with paths", loaderPlan(api.ActionAllow, execRule("tools", api.ActionDeny, "/usr/bin/id")), true},
		{"broad allow is not on purpose", loaderPlan(api.ActionDeny, execRule("all", api.ActionAllow, "/**", "/usr/lib/*")), true},
		{"default allow, no deny", loaderPlan(api.ActionAllow, imageAllow), false},
		{"deny without paths", loaderPlan(api.ActionAllow, api.ExecRule{Rule: api.Rule{Name: "foreign", Action: api.ActionDeny}, Target: api.ExecTarget{PathTarget: api.PathTarget{FromImage: new(bool)}}}), false},
		{"glibc loader allowed on purpose", loaderPlan(api.ActionDeny, execRule("ldso", api.ActionAllow, "/usr/lib64/ld-linux-x86-64.so.2")), false},
		{"musl loader glob allowed on purpose", loaderPlan(api.ActionDeny, execRule("musl", api.ActionAllow, "/lib/ld-musl-*")), false},
		{"old glibc loader allowed on purpose", loaderPlan(api.ActionDeny, execRule("ld231", api.ActionAllow, "/lib/x86_64-linux-gnu/ld-2.31.so")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := loaderRules(t, tc.plan)
			if !tc.want {
				if len(got) != 0 {
					t.Fatalf("unexpected loader rule: %+v", got)
				}
				return
			}
			want := fullpolicy.Rule{Name: "node-agent-loader-deny", Origin: "node-agent/loader", OriginPresent: true, Action: fullpolicy.Deny, Mode: fullpolicy.Enforce, Target: fullpolicy.Target{Path: []string{"/**/ld-*.so*"}}}
			if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
				t.Fatalf("loader rule: %+v", got)
			}
		})
	}
}

func TestFullPoliciesLoaderRuleNameIsFree(t *testing.T) {
	got := loaderRules(t, loaderPlan(api.ActionDeny, execRule("node-agent-loader-deny", api.ActionDeny, "/usr/bin/id"), execRule("node-agent-loader-deny~1", api.ActionDeny, "/usr/bin/su")))
	if len(got) != 1 || got[0].Name != "node-agent-loader-deny~2" {
		t.Fatalf("loader rule name: %+v", got)
	}
}

func TestLoaderGlobMatchesLoadersOnly(t *testing.T) {
	yes := true
	policies, err := fullPolicies(sandboxpolicy.Binding{ContainerName: "app"}, loaderPlan(api.ActionDeny, api.ExecRule{Rule: api.Rule{Name: "image", Action: api.ActionAllow}, Target: api.ExecTarget{PathTarget: api.PathTarget{FromImage: &yes}}}))
	if err != nil {
		t.Fatal(err)
	}
	program, err := fullpolicy.Compile(policies)
	if err != nil {
		t.Fatal(err)
	}
	for path, denied := range map[string]bool{
		"/usr/lib64/ld-linux-x86-64.so.2":            true, // glibc x86_64 (AL2023)
		"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": true, // glibc x86_64 (Debian)
		"/lib/ld-linux-aarch64.so.1":                 true, // glibc aarch64
		"/lib/ld-musl-x86_64.so.1":                   true, // musl x86_64
		"/lib/ld-musl-aarch64.so.1":                  true, // musl aarch64
		"/lib/x86_64-linux-gnu/ld-2.31.so":           true, // glibc before 2.34 (Debian 11)
		"/usr/lib64/ld-2.28.so":                      true, // glibc before 2.34 (RHEL 8)
		"/usr/lib/x86_64-linux-gnu/libc.so.6":        false,
		"/usr/lib64/libm.so.6":                       false,
		"/usr/bin/ld":                                false,
		"/usr/bin/id":                                false,
	} {
		d, err := program.Evaluate(fullpolicy.Facts{TargetPath: path, TargetFromImage: &yes, ActorPath: "/bin/sh", ActorFromImage: &yes, RoleBootstrap: true, Container: "app"})
		if err != nil {
			t.Fatal(path, err)
		}
		if got := d.Action == fullpolicy.Deny; got != denied || d.Block != denied {
			t.Fatalf("%s: denied=%v block=%v, want %v", path, got, d.Block, denied)
		}
	}
}

func TestLoaderRuleTakesTheStrongestDenyModeAndCellCost(t *testing.T) {
	for _, tc := range []struct {
		name       string
		policy     api.PolicyMode
		def        api.Action
		rule       api.RuleMode
		kernelMode uint32
	}{
		{"enforce default deny", "enforce", api.ActionDeny, "", 2},
		{"audit default deny", "audit", api.ActionDeny, "", 1},
		{"enforced deny rule in an audit policy", "audit", api.ActionAllow, api.RuleEnforce, 2},
		{"audit deny rule in an enforce policy", "enforce", api.ActionAllow, api.RuleAudit, 1},
		{"inherited deny rule in an enforce policy", "enforce", api.ActionAllow, "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rules []api.ExecRule
			if tc.def != api.ActionDeny {
				r := execRule("tools", api.ActionDeny, "/usr/bin/id")
				r.Mode = tc.rule
				rules = append(rules, r)
			}
			plan := loaderPlan(tc.def, rules...)
			plan.Policies[0].Mode = tc.policy
			got, err := CompileFull(sandboxpolicy.Binding{ContainerName: "app"}, plan, 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			h, _ := fullpolicy.Decode[fullpolicy.KernelHeader](got.Entries[0])
			last := int(h.RuleCount) - 1
			r, _ := fullpolicy.Decode[fullpolicy.KernelRule](got.Entries[int(h.RuleBase)+last])
			if r.Deny != 1 || r.Mode != tc.kernelMode || got.Rules[last].Origin != loaderOrigin {
				t.Fatalf("header %+v rule %+v provenance %+v", h, r, got.Rules)
			}
			// The shared engine's policy objects hold 256 cells: the loader
			// rule must stay a small part of that budget.
			plan.Policies[0].Exec = api.ExecSection{Default: api.ActionAllow}
			without, err := CompileFull(sandboxpolicy.Binding{ContainerName: "app"}, plan, 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			withOnlyLoader := len(got.Entries) - len(without.Entries)
			if tc.def == api.ActionDeny && withOnlyLoader > 24 {
				t.Fatalf("loader rule costs %d cells", withOnlyLoader)
			}
		})
	}
}

func TestFullVerdictLoaderRuleCarriesItsOrigin(t *testing.T) {
	d := verdictDecoder(t, loaderPlan(api.ActionDeny))
	if len(d.rules) != 1 || d.rules[0].Name != loaderRuleName || !reflect.DeepEqual(d.rules[0].Origins, []string{loaderOrigin}) || d.rules[0].Action != api.ActionDeny {
		t.Fatalf("loader provenance: %+v", d.rules)
	}
}

// The loader rule follows each policy's authored rules. A kernel match bit is
// decoded through the same compiled program, so each user rule still names
// itself and its policy, and the loader bits name the loader rule.
func TestFullVerdictUserRulesKeepTheirNamesWithLoaderRules(t *testing.T) {
	p := verdictPlan()
	d := verdictDecoder(t, p)
	var want []string
	for _, policy := range p.Policies { // fullPlan's UIDs are already sorted
		for _, r := range policy.Exec.Rules {
			want = append(want, string(policy.Identity.UID)+"/"+r.Name)
		}
		want = append(want, string(policy.Identity.UID)+"/"+loaderRuleName)
	}
	var got []string
	for i, r := range d.rules {
		deny, mode := uint32(0), uint32(2)
		if r.Action == api.ActionDeny {
			deny = 1
		}
		if r.Mode == api.RuleAudit {
			mode = 1
		}
		v, err := d.Decode(RawFullVerdict{RawVerdict: RawVerdict{Generation: 7, Cgroup: 19, Deny: deny, Mode: mode}, MatchedRules: [4]uint64{1 << uint(i)}})
		if err != nil || len(v.Matches) != 1 {
			t.Fatalf("bit %d: %+v %v", i, v, err)
		}
		got = append(got, string(v.Matches[0].Policy.UID)+"/"+v.Matches[0].Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded rules %v, want %v", got, want)
	}
}
