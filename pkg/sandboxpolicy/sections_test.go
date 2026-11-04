package sandboxpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func privilegeSection(def api.Action) *api.PrivilegeSection {
	return &api.PrivilegeSection{Default: def, Rules: []api.PrivilegeRule{{Rule: api.Rule{Name: "no-mount", Action: api.ActionDeny}, Target: api.PrivilegeTarget{Syscall: []string{"mount"}}}}}
}

func sectionPlan(revision string, policies ...CompiledPolicy) Plan {
	return Plan{Revision: revision, Policies: policies}
}

func TestSectionBackendExecOnlyPlanIsUnchanged(t *testing.T) {
	exec, privilege := &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}
	s, err := NewSectionBackend(exec, privilege, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := sectionPlan("aggregate", CompiledPolicy{Revision: "p1", Exec: api.ExecSection{Default: api.ActionDeny}})
	r, err := s.Replace(context.Background(), Binding{ContainerID: "c"}, plan)
	if err != nil || !r.Committed || r.ActiveRevision != "aggregate" {
		t.Fatalf("replace: %+v %v", r, err)
	}
	if got := exec.plans[bindingKey(Binding{ContainerID: "c"})]; got.Revision != "aggregate" {
		t.Fatalf("exec got %+v", got)
	}
	if privilege.replacements+privilege.withdrawals != 0 {
		t.Fatal("privilege backend must not be called for an exec-only plan")
	}
	if err := s.Attest(context.Background(), Binding{ContainerID: "c"}, "aggregate"); err != nil {
		t.Fatal(err)
	}
}

func TestSectionBackendSplitsAndKeepsUnchangedSection(t *testing.T) {
	exec, privilege := &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}
	s, _ := NewSectionBackend(exec, privilege, nil)
	b := Binding{ContainerID: "c"}
	execPolicy := CompiledPolicy{Revision: "e", Exec: api.ExecSection{Default: api.ActionDeny}}
	privPolicy := CompiledPolicy{Revision: "p", Privilege: privilegeSection(api.ActionAllow)}
	if _, err := s.Replace(context.Background(), b, sectionPlan("r1", execPolicy, privPolicy)); err != nil {
		t.Fatal(err)
	}
	if len(exec.plans[bindingKey(b)].Policies) != 1 || exec.plans[bindingKey(b)].Policies[0].Privilege != nil {
		t.Fatalf("exec plan %+v", exec.plans[bindingKey(b)])
	}
	if len(privilege.plans[bindingKey(b)].Policies) != 1 {
		t.Fatalf("privilege plan %+v", privilege.plans[bindingKey(b)])
	}
	// An exec-only change keeps the privilege revision: no privilege restart.
	execPolicy.Revision = "e2"
	execPolicy.Exec.Default = api.ActionAllow
	if _, err := s.Replace(context.Background(), b, sectionPlan("r2", execPolicy, privPolicy)); err != nil {
		t.Fatal(err)
	}
	if exec.replacements != 2 || privilege.replacements != 1 {
		t.Fatalf("exec %d privilege %d replacements", exec.replacements, privilege.replacements)
	}
	// Dropping the privilege policy withdraws only the privilege section.
	if _, err := s.Replace(context.Background(), b, sectionPlan("r3", execPolicy)); err != nil {
		t.Fatal(err)
	}
	if privilege.withdrawals != 1 || exec.withdrawals != 0 {
		t.Fatalf("withdrawals exec %d privilege %d", exec.withdrawals, privilege.withdrawals)
	}
}

func TestSectionBackendPrivilegeFailureRestoresExec(t *testing.T) {
	exec, privilege := &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}, fail: true}
	s, _ := NewSectionBackend(exec, privilege, nil)
	b := Binding{ContainerID: "c"}
	execPolicy := CompiledPolicy{Revision: "e", Exec: api.ExecSection{Default: api.ActionDeny}}
	r, err := s.Replace(context.Background(), b, sectionPlan("r1", execPolicy, CompiledPolicy{Revision: "p", Privilege: privilegeSection(api.ActionAllow)}))
	if err == nil || r.Committed {
		t.Fatalf("expected failure, got %+v", r)
	}
	if _, ok := exec.plans[bindingKey(b)]; ok || exec.withdrawals != 1 {
		t.Fatalf("exec must return to its previous (empty) state: %+v withdrawals=%d", exec.plans, exec.withdrawals)
	}
}

func TestSectionBackendRejectsPrivilegeWithoutImage(t *testing.T) {
	s, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, nil, nil)
	if _, err := s.Replace(context.Background(), Binding{}, sectionPlan("r", CompiledPolicy{Privilege: privilegeSection(api.ActionDeny)})); err == nil {
		t.Fatal("privilege must be rejected without a privilege backend")
	}
}

func TestCompileKeepsPrivilegeSection(t *testing.T) {
	spec := execSpec()
	spec.Privilege = privilegeSection(api.ActionAllow)
	got, err := Compile(context.Background(), PolicyIdentity{}, spec, api.PolicyClasses{}, Binding{}, nil)
	if err != nil || got.Privilege == nil || got.Privilege.Rules[0].Name != "no-mount" {
		t.Fatalf("compile: %+v %v", got.Privilege, err)
	}
	spec.Privilege.Default = "maybe"
	if _, err := Compile(context.Background(), PolicyIdentity{}, spec, api.PolicyClasses{}, Binding{}, nil); err == nil {
		t.Fatal("invalid privilege default accepted")
	}
}

func TestSectionBackendKeepsCommittedCleanupErrors(t *testing.T) {
	// Exec-only: the exec backend result passes through unchanged.
	exec := &fakeBackend{plans: map[string]Plan{}, postCommit: true}
	s, _ := NewSectionBackend(exec, &fakeBackend{plans: map[string]Plan{}}, nil)
	b := Binding{ContainerID: "c"}
	r, err := s.Replace(context.Background(), b, sectionPlan("r1", CompiledPolicy{Exec: api.ExecSection{Default: api.ActionDeny}}))
	if err == nil || !r.Committed || r.ActiveRevision != "r1" {
		t.Fatalf("exec-only cleanup error must stay committed: %+v %v", r, err)
	}
	// With privilege: a committed section with a cleanup error does not roll back.
	privilege := &fakeBackend{plans: map[string]Plan{}, postCommit: true}
	s, _ = NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, privilege, nil)
	r, err = s.Replace(context.Background(), b, sectionPlan("r2", CompiledPolicy{Privilege: privilegeSection(api.ActionAllow)}))
	if err == nil || !r.Committed || r.ActiveRevision != "r2" {
		t.Fatalf("privilege cleanup error must stay committed: %+v %v", r, err)
	}
}

func TestSectionBackendPrivilegeChangeKeepsExecRevision(t *testing.T) {
	exec, privilege := &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}
	s, _ := NewSectionBackend(exec, privilege, nil)
	b := Binding{ContainerID: "c"}
	p := CompiledPolicy{Revision: "v1", Exec: api.ExecSection{Default: api.ActionDeny}, Privilege: privilegeSection(api.ActionAllow)}
	if _, err := s.Replace(context.Background(), b, sectionPlan("r1", p)); err != nil {
		t.Fatal(err)
	}
	p.Revision = "v2" // the compiler's policy revision changes with the privilege section
	p.Privilege = privilegeSection(api.ActionDeny)
	if _, err := s.Replace(context.Background(), b, sectionPlan("r2", p)); err != nil {
		t.Fatal(err)
	}
	if exec.replacements != 1 || privilege.replacements != 2 {
		t.Fatalf("exec %d privilege %d replacements", exec.replacements, privilege.replacements)
	}
}

func TestSectionBackendSendsAllPrivilegePolicies(t *testing.T) {
	privilege := &fakeBackend{plans: map[string]Plan{}}
	s, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, privilege, nil)
	b := Binding{ContainerID: "c"}
	p1 := CompiledPolicy{Identity: PolicyIdentity{UID: "1"}, Privilege: privilegeSection(api.ActionAllow)}
	p2 := CompiledPolicy{Identity: PolicyIdentity{UID: "2"}, Privilege: privilegeSection(api.ActionDeny)}
	if _, err := s.Replace(context.Background(), b, sectionPlan("r", p1, p2)); err != nil {
		t.Fatal(err)
	}
	if got := privilege.plans[bindingKey(b)]; len(got.Policies) != 2 {
		t.Fatalf("privilege plan %+v", got)
	}
}

type preparingBackend struct {
	fakeBackend
	prepared []Plan
	calls    int
}

func (p *preparingBackend) Prepare(_ context.Context, plans []Plan) error {
	p.prepared = plans
	p.calls++
	return nil
}

func TestSectionBackendPassesPrepare(t *testing.T) {
	privilege := &preparingBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	s, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, privilege, nil)
	if err := s.Prepare(context.Background(), []Plan{sectionPlan("r", CompiledPolicy{Privilege: privilegeSection(api.ActionDeny)})}); err != nil || len(privilege.prepared) != 1 {
		t.Fatalf("prepare: %v %v", err, privilege.prepared)
	}
	// A section with no active policy is not prepared: privilege loads its
	// gadget on an empty prepare, which a network-only node must not do.
	privilege.prepared = nil
	network := &preparingBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	s.WithNetwork(network, nil)
	plans := []Plan{sectionPlan("r", CompiledPolicy{Network: networkPlan()})}
	if err := s.PrepareSections(context.Background(), plans, map[string]bool{SectionNetwork: true}); err != nil || privilege.prepared != nil || len(network.prepared) != 1 {
		t.Fatalf("prepare sections: %v privilege=%v network=%v", err, privilege.prepared, network.prepared)
	}
}

func TestSectionBackendModeChangeReachesPrivilege(t *testing.T) {
	privilege := &fakeBackend{plans: map[string]Plan{}}
	s, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, privilege, nil)
	b := Binding{ContainerID: "c"}
	p := CompiledPolicy{Mode: api.ModeAudit, Privilege: privilegeSection(api.ActionAllow)}
	if _, err := s.Replace(context.Background(), b, sectionPlan("r1", p)); err != nil {
		t.Fatal(err)
	}
	p.Mode = api.ModeEnforce
	if _, err := s.Replace(context.Background(), b, sectionPlan("r2", p)); err != nil {
		t.Fatal(err)
	}
	if privilege.replacements != 2 {
		t.Fatalf("mode change must replace the privilege instance, replacements=%d", privilege.replacements)
	}
}

func TestSectionBackendRetriesPrivilegeCleanup(t *testing.T) {
	privilege := &fakeBackend{plans: map[string]Plan{}}
	s, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, privilege, nil)
	b := Binding{ContainerID: "c"}
	if _, err := s.Replace(context.Background(), b, sectionPlan("r1", CompiledPolicy{Privilege: privilegeSection(api.ActionAllow)})); err != nil {
		t.Fatal(err)
	}
	privilege.withdrawPostCommit = true
	r, err := s.Withdraw(context.Background(), b)
	if err == nil || !r.Committed {
		t.Fatalf("committed withdraw with cleanup error expected: %+v %v", r, err)
	}
	privilege.withdrawPostCommit = false
	if r, err = s.Withdraw(context.Background(), b); err != nil || !r.Committed || privilege.withdrawals != 2 {
		t.Fatalf("retry must reach the privilege backend: %+v %v withdrawals=%d", r, err, privilege.withdrawals)
	}
	if _, ok := s.active[bindingKey(b)]; ok {
		t.Fatal("state must be gone after a clean retry")
	}
}

func TestSectionBackendPartialWithdrawIsUnconfirmed(t *testing.T) {
	privilege := &fakeBackend{plans: map[string]Plan{}}
	s, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, privilege, nil)
	b := Binding{ContainerID: "c"}
	p := CompiledPolicy{Exec: api.ExecSection{Default: api.ActionDeny}, Privilege: privilegeSection(api.ActionAllow)}
	if _, err := s.Replace(context.Background(), b, sectionPlan("r1", p)); err != nil {
		t.Fatal(err)
	}
	privilege.fail = true
	if r, _ := s.Withdraw(context.Background(), b); r.Committed || !r.ProtectionUnconfirmed {
		t.Fatalf("exec removed but privilege not: %+v", r)
	}
}

func TestControllerPrepareScheduled(t *testing.T) {
	ctx := context.Background()
	withPrivilege := policy("with-privilege", "ns")
	withPrivilege.Spec.Privilege = privilegeSection(api.ActionDeny)
	execOnly := policy("exec-only", "ns")
	c, _, _, _ := setup(t, withPrivilege, execOnly)
	preparer := &preparingBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	c.backend = preparer
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	template := binding()
	template.ContainerID, template.CgroupID = "", 0 // a scheduled pod: no runtime identity yet
	other := template
	other.Namespace = "elsewhere"
	if err := c.PrepareScheduled(ctx, []Binding{template, other}); err != nil {
		t.Fatal(err)
	}
	if len(preparer.prepared) != 1 || len(preparer.prepared[0].Policies) != 1 || preparer.prepared[0].Policies[0].Identity.Name != "with-privilege" {
		t.Fatalf("prepared %+v", preparer.prepared)
	}
}

func TestPrivilegeUnavailableIsReportedAndRefused(t *testing.T) {
	ctx := context.Background()
	p := policy("with-privilege", "ns")
	p.Spec.Privilege = privilegeSection(api.ActionDeny)
	c, _, w, _ := setup(t, p)
	lsm := &EnforcementUnavailableError{Section: "privilege", Reason: "BPFLSMInactive", Detail: "BPF LSM is not active"}
	sections, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, nil, lsm)
	c.backend = sections
	if err := c.InitialSync(ctx); err != nil && !errors.Is(err, lsm) {
		t.Fatalf("initial sync: %v", err)
	}
	report := w.reports[string(p.UID)]
	if report == nil || len(report.Status.Conditions) == 0 {
		t.Fatal("no status report")
	}
	ready := report.Status.Conditions[0]
	if ready.Status != metav1.ConditionFalse || ready.Reason != "BPFLSMInactive" {
		t.Fatalf("ready condition %+v", ready)
	}
	if _, err := sections.Replace(ctx, Binding{ContainerID: "c"}, sectionPlan("r", CompiledPolicy{Privilege: privilegeSection(api.ActionDeny)})); !errors.Is(err, lsm) {
		t.Fatalf("privilege binding must be refused: %v", err)
	}
}

func networkPlan() *NetworkPlan {
	return &NetworkPlan{Egress: netpolicy.Document{Version: 1, Policy: netpolicy.Policy{Mode: "enforce", Egress: netpolicy.Section{Default: "allow"}}}}
}

func TestSectionBackendRoutesNetworkSection(t *testing.T) {
	exec, privilege, network := &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}
	s, _ := NewSectionBackend(exec, privilege, nil)
	s.WithNetwork(network, nil)
	b := Binding{ContainerID: "c"}
	p := CompiledPolicy{Identity: PolicyIdentity{UID: "1"}, Exec: api.ExecSection{Default: api.ActionDeny}, Network: networkPlan()}
	if _, err := s.Replace(context.Background(), b, sectionPlan("r1", p)); err != nil {
		t.Fatal(err)
	}
	if got := network.plans[bindingKey(b)]; len(got.Policies) != 1 || got.Policies[0].Network == nil {
		t.Fatalf("network plan %+v", got)
	}
	if got := exec.plans[bindingKey(b)]; len(got.Policies) != 1 || got.Policies[0].Network != nil {
		t.Fatalf("exec plan must not carry the network section: %+v", got)
	}
	if privilege.replacements != 0 {
		t.Fatal("privilege backend must not be called")
	}
	if err := s.Attest(context.Background(), b, "r1"); err != nil {
		t.Fatal(err)
	}
	// A network change keeps the exec revision.
	p.Network = networkPlan()
	p.Network.Egress.Policy.Egress.Default = "deny"
	if _, err := s.Replace(context.Background(), b, sectionPlan("r2", p)); err != nil || exec.replacements != 1 || network.replacements != 2 {
		t.Fatalf("exec %d network %d replacements, %v", exec.replacements, network.replacements, err)
	}
	if r, err := s.Withdraw(context.Background(), b); err != nil || !r.Committed || network.withdrawals != 1 || len(s.active) != 0 {
		t.Fatalf("withdraw %+v %v", r, err)
	}
}

func TestSectionBackendNetworkFailureRestoresEarlierSections(t *testing.T) {
	exec, privilege, network := &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}, fail: true}
	s, _ := NewSectionBackend(exec, privilege, nil)
	s.WithNetwork(network, nil)
	b := Binding{ContainerID: "c"}
	p := CompiledPolicy{Identity: PolicyIdentity{UID: "1"}, Exec: api.ExecSection{Default: api.ActionDeny}, Privilege: privilegeSection(api.ActionAllow), Network: networkPlan()}
	if r, err := s.Replace(context.Background(), b, sectionPlan("r1", p)); err == nil || r.Committed {
		t.Fatalf("expected failure: %+v", r)
	}
	if len(exec.plans)+len(privilege.plans) != 0 || exec.withdrawals != 1 || privilege.withdrawals != 1 {
		t.Fatalf("exec and privilege must return to their previous state: exec %+v privilege %+v", exec.plans, privilege.plans)
	}
}

func TestSectionBackendRejectsNetworkWithoutImage(t *testing.T) {
	s, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}, nil)
	_, err := s.Replace(context.Background(), Binding{}, sectionPlan("r", CompiledPolicy{Network: networkPlan()}))
	var u *EnforcementUnavailableError
	if !errors.As(err, &u) || u.Reason != "NetworkNotConfigured" || s.SectionUnavailable(SectionNetwork) == nil || s.SectionUnavailable(SectionPrivilege) != nil {
		t.Fatalf("network must be rejected without a network backend: %v", err)
	}
}

// The controller gives a plan the digest of its policies as revision. Adding a
// privilege policy to an exec-only binding, and removing it again, must keep
// the exec revision, so exec does not restart.
func TestSectionBackendSeparatePrivilegePolicyKeepsExecRevision(t *testing.T) {
	exec, privilege := &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}
	s, _ := NewSectionBackend(exec, privilege, nil)
	b := Binding{ContainerID: "c"}
	execPolicy := CompiledPolicy{Identity: PolicyIdentity{UID: "e", Generation: 3}, Revision: "e", Exec: api.ExecSection{Default: api.ActionDeny}}
	privPolicy := CompiledPolicy{Identity: PolicyIdentity{UID: "p", Generation: 1}, Revision: "p", Privilege: privilegeSection(api.ActionAllow)}
	plan := func(policies ...CompiledPolicy) Plan { return Plan{Revision: digest(policies), Policies: policies} }
	steps := []Plan{plan(execPolicy), plan(execPolicy, privPolicy), plan(execPolicy)}
	privPolicy.Identity.Generation = 2 // an edit of the privilege policy object
	privPolicy.Privilege = privilegeSection(api.ActionDeny)
	steps = append(steps[:2], plan(execPolicy, privPolicy), steps[2])
	for i, p := range steps {
		r, err := s.Replace(context.Background(), b, p)
		if err != nil || !r.Committed || r.ActiveRevision != p.Revision {
			t.Fatalf("step %d: %+v %v", i, r, err)
		}
	}
	if exec.replacements != 1 {
		t.Fatalf("exec restarted: %d replacements", exec.replacements)
	}
	if privilege.replacements != 2 || privilege.withdrawals != 1 {
		t.Fatalf("privilege %d replacements %d withdrawals", privilege.replacements, privilege.withdrawals)
	}
}

// Adding a separate network policy to an exec-only binding, editing it and
// removing it again must keep the exec revision, so exec does not restart.
func TestSectionBackendSeparateNetworkPolicyKeepsExecRevision(t *testing.T) {
	exec, privilege, network := &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}
	s, _ := NewSectionBackend(exec, privilege, nil)
	s.WithNetwork(network, nil)
	b := Binding{ContainerID: "c"}
	execPolicy := CompiledPolicy{Identity: PolicyIdentity{UID: "e", Generation: 3}, Revision: "e", Exec: api.ExecSection{Default: api.ActionDeny}}
	netPolicy := CompiledPolicy{Identity: PolicyIdentity{UID: "n", Generation: 1}, Revision: "n", Network: networkPlan()}
	plan := func(policies ...CompiledPolicy) Plan { return Plan{Revision: digest(policies), Policies: policies} }
	steps := []Plan{plan(execPolicy), plan(execPolicy, netPolicy)}
	netPolicy.Identity.Generation = 2 // an edit of the network policy object
	netPolicy.Network = networkPlan()
	netPolicy.Network.Egress.Policy.Egress.Default = "deny"
	steps = append(steps, plan(execPolicy, netPolicy), plan(execPolicy))
	for i, p := range steps {
		r, err := s.Replace(context.Background(), b, p)
		if err != nil || !r.Committed || r.ActiveRevision != p.Revision {
			t.Fatalf("step %d: %+v %v", i, r, err)
		}
	}
	if exec.replacements != 1 {
		t.Fatalf("exec restarted: %d replacements", exec.replacements)
	}
	if network.replacements != 2 || network.withdrawals != 1 || privilege.replacements != 0 {
		t.Fatalf("network %d replacements %d withdrawals, privilege %d", network.replacements, network.withdrawals, privilege.replacements)
	}
}

func TestControllerPodPlans(t *testing.T) {
	ctx := context.Background()
	all := policy("all", "ns")
	all.Spec.Privilege = privilegeSection(api.ActionDeny)
	app := policy("app-only", "ns")
	app.Spec.Containers = []string{"app"}
	app.Spec.Privilege = privilegeSection(api.ActionAllow)
	c, _, _, _ := setup(t, all, app)
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	container := func(pod types.UID, name, kind string) Binding {
		b := binding()
		b.ContainerID, b.CgroupID, b.PodUID, b.ContainerName, b.Kind = "", 0, pod, name, kind
		return b
	}
	elsewhere := container("other-ns", "web", "regular")
	elsewhere.Namespace = "elsewhere"
	plans, ok := c.PodPlans([]Binding{
		container("uniform", "web", "regular"), container("uniform", "db", "regular"),
		container("init", "web", "regular"), container("init", "setup", "init"),
		container("mixed", "web", "regular"), container("mixed", "app", "regular"),
		elsewhere,
	})
	if !ok || len(plans) != 1 || len(plans["uniform"].Policies) != 1 || plans["uniform"].Policies[0].Identity.Name != "all" {
		t.Fatalf("only the pod whose containers all get the same policies has a pod plan: %+v", plans)
	}
}

func TestControllerPodPlansNeedContainerEligibility(t *testing.T) {
	ctx := context.Background()
	priv := policy("priv", "ns")
	priv.Spec.Privilege = privilegeSection(api.ActionDeny)
	// A second policy that selects the same container but depends on a
	// ContainerProfile: the container binding can fail, so no pod binding.
	sourced := policy("sourced", "ns")
	sourced.Spec.Selector.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"profile": "yes"}}
	sourced.Spec.Sources = []api.PolicySource{{ContainerProfile: api.ContainerProfileReference{Name: "profile"}, Include: []string{"execs"}}}
	c, _, _, _ := setup(t, priv, sourced)
	if err := c.InitialSync(ctx); err != nil && !strings.Contains(err.Error(), "ContainerProfile") {
		t.Fatal(err)
	}
	plain := binding()
	plain.ContainerID, plain.CgroupID, plain.PodUID = "", 0, "plain"
	profiled := plain
	profiled.PodUID = "profiled"
	profiled.PodLabels = map[string]string{"app": "test", "profile": "yes"}
	plans, ok := c.PodPlans([]Binding{plain, profiled})
	if !ok || len(plans) != 1 || len(plans["plain"].Policies) != 1 {
		t.Fatalf("only the pod without a sourced policy has a pod plan: %+v", plans)
	}
}

// A section that becomes inactive is prepared once with no plans, so its
// prepared slots are dropped; later calls leave it alone.
func TestSectionBackendClearsPreparedSectionOnceWhenInactive(t *testing.T) {
	privilege := &preparingBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	s, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, privilege, nil)
	ctx := context.Background()
	plans := []Plan{sectionPlan("r", CompiledPolicy{Privilege: privilegeSection(api.ActionDeny)})}
	if err := s.PrepareSections(ctx, plans, map[string]bool{SectionPrivilege: true}); err != nil || privilege.calls != 1 || len(privilege.prepared) != 1 {
		t.Fatalf("active: %v calls=%d prepared=%v", err, privilege.calls, privilege.prepared)
	}
	for i := 0; i < 2; i++ {
		if err := s.PrepareSections(ctx, nil, map[string]bool{}); err != nil {
			t.Fatal(err)
		}
	}
	if privilege.calls != 2 || privilege.prepared != nil {
		t.Fatalf("inactive: calls=%d prepared=%v", privilege.calls, privilege.prepared)
	}
}
