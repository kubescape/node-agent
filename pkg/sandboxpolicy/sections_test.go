package sandboxpolicy

import (
	"context"
	"errors"
	"testing"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
}

func (p *preparingBackend) Prepare(_ context.Context, plans []Plan) error {
	p.prepared = plans
	return nil
}

func TestSectionBackendPassesPrepare(t *testing.T) {
	privilege := &preparingBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	s, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, privilege, nil)
	if err := s.Prepare(context.Background(), []Plan{sectionPlan("r", CompiledPolicy{Privilege: privilegeSection(api.ActionDeny)})}); err != nil || len(privilege.prepared) != 1 {
		t.Fatalf("prepare: %v %v", err, privilege.prepared)
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
