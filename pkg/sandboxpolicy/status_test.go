package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestStatusIdentityBoundsAndUnprotected(t *testing.T) {
	c, _, _, _ := setup(t)
	p := parseTypedPolicy(t, policy("policy", "ns"))
	r := c.report(p, errors.New(strings.Repeat("x", api.MaxStatusErrorLength+1)))
	if r.Name != api.NodeStatusName("policy", "node-uid") || r.Spec.PolicyRef.UID != "policy" || r.Spec.NodeRef.UID != "node-uid" || len(r.OwnerReferences) != 1 || r.OwnerReferences[0].UID != "policy" {
		t.Fatalf("identity/ownership: %+v", r)
	}
	if !r.Status.Truncated || len(r.Status.Error) != api.MaxStatusErrorLength || r.Status.Conditions[0].Status != metav1.ConditionFalse || !strings.Contains(r.Status.Conditions[0].Message, "no last-good") {
		t.Fatalf("incorrect failure: %+v", r.Status)
	}
	if r.Status.AppliedGeneration != 0 {
		t.Fatalf("applied generation %d with no installed binding", r.Status.AppliedGeneration)
	}
}

func parseTypedPolicy(t *testing.T, p *api.SandboxPolicy) desiredPolicy {
	t.Helper()
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
	if err != nil {
		t.Fatal(err)
	}
	return parsePolicy(&unstructured.Unstructured{Object: raw})
}

func TestDynamicStatusWriterCreateHeartbeatAndIdentity(t *testing.T) {
	ctx := context.Background()
	c, _, _, client := setup(t)
	r := c.report(parseTypedPolicy(t, policy("policy", "ns")), nil)
	writer := DynamicStatusWriter{Client: client}
	if err := writer.WriteStatus(ctx, r); err != nil {
		t.Fatal(err)
	}
	current, err := client.Resource(NodeStatusGVR).Namespace("ns").Get(ctx, r.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var first api.SandboxPolicyNodeStatus
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(current.Object, &first); err != nil {
		t.Fatal(err)
	}
	r.Status.Conditions[0].LastTransitionTime = metav1.Now()
	if err := writer.WriteStatus(ctx, r); err != nil {
		t.Fatal(err)
	}
	current, err = client.Resource(NodeStatusGVR).Namespace("ns").Get(ctx, r.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var second api.SandboxPolicyNodeStatus
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(current.Object, &second); err != nil {
		t.Fatal(err)
	}
	if !first.Status.Conditions[0].LastTransitionTime.Equal(&second.Status.Conditions[0].LastTransitionTime) {
		t.Fatal("heartbeat changed transition timestamp")
	}
	r.Spec.NodeRef.UID = "other"
	if err := writer.WriteStatus(ctx, r); err == nil {
		t.Fatal("accepted different report identity")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "update" && action.GetSubresource() != "status" {
			t.Fatal("updated spec/parent instead of status")
		}
	}
}

func TestAppliedGenerationIsOldestConfirmedBinding(t *testing.T) {
	c, _, _, _ := setup(t)
	p := parseTypedPolicy(t, policy("policy", "ns"))
	p.identity.Generation = 3
	installedAt := func(container string, generation int64, unconfirmed bool) {
		b := binding()
		b.ContainerID = container
		c.active[bindingKey(b)] = installed{binding: b, protectionUnconfirmed: unconfirmed, plan: Plan{Policies: []CompiledPolicy{{Identity: PolicyIdentity{UID: p.identity.UID, Generation: generation}, Revision: container}}}}
	}
	installedAt("new", 3, false)
	installedAt("old", 2, false)
	installedAt("unconfirmed", 1, true) // cannot vouch for it
	if r := c.report(p, nil); r.Status.AppliedGeneration != 2 || r.Status.Tier != "bpf-lsm" {
		t.Fatalf("status %+v, want applied generation 2", r.Status)
	}
	c.options.EnforcementUnavailable = &EnforcementUnavailableError{Section: "sandbox policy", Reason: "BPFLSMInactive", Detail: "BPF LSM is not active"}
	if r := c.report(p, nil); r.Status.AppliedGeneration != 0 || r.Status.Tier != "none" {
		t.Fatalf("status %+v, want no applied generation with tier none", r.Status)
	}
}

func TestRefusedPrivilegeKeepsTierOfActiveExecBindings(t *testing.T) {
	c, _, _, _ := setup(t)
	withPrivilege := policy("policy", "ns")
	withPrivilege.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, withPrivilege)
	sections, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, nil, nil) // PrivilegeNotConfigured
	c.backend = sections
	if r := c.report(p, nil); r.Status.Tier != "none" || r.Status.Conditions[0].Reason != "PrivilegeNotConfigured" {
		t.Fatalf("no active binding: %+v", r.Status)
	}
	b := binding()
	c.active[bindingKey(b)] = installed{binding: b, plan: Plan{Policies: []CompiledPolicy{{Identity: PolicyIdentity{UID: p.identity.UID, Generation: 1}, Revision: "r"}}}}
	if r := c.report(p, nil); r.Status.Tier != "bpf-lsm" || r.Status.Conditions[0].Reason != "PrivilegeNotConfigured" {
		t.Fatalf("last-good exec binding: %+v", r.Status)
	}
}

type podReportingBackend struct {
	fakeBackend
	pods, faulted []Plan
}

func (b *podReportingBackend) BoundPodPlans() (confirmed, faulted []Plan) { return b.pods, b.faulted }

// A pod binding whose slot has a fault cannot be confirmed: it never counts as
// enforcement, and the policy reports that protection is unconfirmed.
func TestFaultedPodBindingIsUnconfirmed(t *testing.T) {
	c, _, _, _ := setup(t)
	p := parseTypedPolicy(t, policy("policy", "ns"))
	p.identity.Generation = 3
	backend := &podReportingBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	backend.faulted = []Plan{{Policies: []CompiledPolicy{{Identity: PolicyIdentity{UID: p.identity.UID, Generation: 3}}}}}
	c.backend = backend
	r := c.report(p, nil)
	if r.Status.AppliedGeneration != 0 || r.Status.Conditions[0].Status != metav1.ConditionFalse || r.Status.Conditions[0].Reason != "ProtectionUnconfirmed" {
		t.Fatalf("status %+v", r.Status)
	}
}

// A pod cgroup binding enforces even when the container binding failed, so the
// report must not say that nothing enforces.
func TestPodBindingsCountAsEnforcement(t *testing.T) {
	c, _, _, _ := setup(t)
	p := parseTypedPolicy(t, policy("policy", "ns"))
	p.identity.Generation = 3
	backend := &podReportingBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	backend.pods = []Plan{{Policies: []CompiledPolicy{
		{Identity: PolicyIdentity{UID: p.identity.UID, Generation: 2}, Revision: "r2"},
		{Identity: PolicyIdentity{UID: "other", Generation: 1}, Revision: "o"},
	}}}
	c.backend = backend
	r := c.report(p, errors.New("container binding refused"))
	if r.Status.AppliedGeneration != 2 || r.Status.Tier != "bpf-lsm" || !r.Status.Stale {
		t.Fatalf("status %+v", r.Status)
	}
	if strings.Contains(r.Status.Conditions[0].Message, "no last-good") {
		t.Fatalf("pod binding ignored: %q", r.Status.Conditions[0].Message)
	}
}

// Bindings on the desired generation are not stale, even when another binding
// failed; pod plans carry no revision, so ActiveRevision shows none.
func TestPartialFailureOnCurrentGenerationIsNotStale(t *testing.T) {
	c, _, _, _ := setup(t)
	p := parseTypedPolicy(t, policy("policy", "ns"))
	p.identity.Generation = 3
	backend := &podReportingBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	backend.pods = []Plan{{Policies: []CompiledPolicy{{Identity: PolicyIdentity{UID: p.identity.UID, Generation: 3}}}}}
	c.backend = backend
	r := c.report(p, errors.New("exec binding refused"))
	if r.Status.Stale || r.Status.AppliedGeneration != 3 || r.Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatalf("status %+v", r.Status)
	}
	if !strings.Contains(r.Status.Conditions[0].Message, "applied in part") {
		t.Fatalf("message %q", r.Status.Conditions[0].Message)
	}
	if active := r.Status.Conditions[1]; active.Type != "ActiveRevision" || active.Message != "generation=3" {
		t.Fatalf("active revision %+v", active)
	}
}

// Without BPF LSM the message names the node-wide cause, not the first
// section that also failed for it.
func TestNodeWideUnavailableMessageWins(t *testing.T) {
	c, _, _, _ := setup(t)
	withPrivilege := policy("policy", "ns")
	withPrivilege.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, withPrivilege)
	c.options.EnforcementUnavailable = &EnforcementUnavailableError{Section: "sandbox policy", Reason: "BPFLSMInactive", Detail: "BPF LSM is not active"}
	section := &EnforcementUnavailableError{Section: "privilege", Reason: "BPFLSMInactive", Detail: "BPF LSM is not active"}
	r := c.report(p, section)
	if ready := r.Status.Conditions[0]; ready.Reason != "BPFLSMInactive" || !strings.HasPrefix(ready.Message, "sandbox policy enforcement") {
		t.Fatalf("ready %+v", ready)
	}
}

// On a kernel outside the section's list the privilege section is not loaded:
// a privilege policy is Ready False with the kernel check's reason, tier none,
// and nothing binds its privilege section.
func TestKernelRefusedSectionIsNotLoaded(t *testing.T) {
	c, _, _, _ := setup(t)
	withPrivilege := policy("policy", "ns")
	withPrivilege.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, withPrivilege)
	sections, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, nil, &EnforcementUnavailableError{Section: "privilege", Reason: "PrivilegeKernelUnqualified", Detail: "kernel check btf: not a qualified kernel build"})
	c.backend = sections
	r := c.report(p, nil)
	if r.Status.Conditions[0].Status != metav1.ConditionFalse || r.Status.Conditions[0].Reason != "PrivilegeKernelUnqualified" || r.Status.Tier != "none" {
		t.Fatalf("refused kernel: %s %+v", r.Status.Tier, r.Status.Conditions[0])
	}
	if res, err := sections.Replace(context.Background(), Binding{ContainerID: "c"}, sectionPlan("r", CompiledPolicy{Revision: "p", Privilege: privilegeSection(api.ActionDeny)})); err == nil || res.Committed {
		t.Fatalf("a refused section never binds: %+v %v", res, err)
	}
	// A selected container whose exec part committed without the refused
	// section is unconfirmed; the kernel check still names the cause.
	b := binding()
	c.active[bindingKey(b)] = installed{binding: b, protectionUnconfirmed: true, plan: Plan{Policies: []CompiledPolicy{{Identity: PolicyIdentity{UID: p.identity.UID, Generation: p.identity.Generation}, Revision: "r"}}}}
	if r := c.report(p, nil); r.Status.Conditions[0].Reason != "PrivilegeKernelUnqualified" || !r.Status.Stale {
		t.Fatalf("refused kernel with a selected container: %v %+v", r.Status.Stale, r.Status.Conditions[0])
	}
}

// The runtime check is skipped where nothing of the section is loaded or
// enforced: a policy that is off, or a node without BPF LSM.
func TestKernelRuntimeSkipped(t *testing.T) {
	c, _, _, _ := setup(t)
	withPrivilege := policy("policy", "ns")
	withPrivilege.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, withPrivilege)
	sections, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}, nil)
	c.backend = sections
	c.options.KernelRuntime = func(string) error {
		t.Fatal("no runtime check expected")
		return nil
	}
	off := p
	off.spec.Mode = api.ModeOff
	c.report(off, nil)
	c.options.EnforcementUnavailable = &EnforcementUnavailableError{Section: "node", Reason: "BPFLSMInactive", Detail: "bpf is not an active LSM"}
	if r := c.report(p, nil); r.Status.Conditions[0].Reason != "BPFLSMInactive" {
		t.Fatalf("node without BPF LSM: %+v", r.Status.Conditions[0])
	}
}

// Ftrace off (or a livepatch) is re-read at every status write. While it fails,
// every binding of a loaded section is unprotected: Ready False with the
// check's reason, tier none and no applied generation.
func TestKernelRuntimeFailureIsUnprotected(t *testing.T) {
	c, _, _, _ := setup(t)
	withPrivilege := policy("policy", "ns")
	withPrivilege.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, withPrivilege)
	sections, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}, nil)
	c.backend = sections
	b := binding()
	c.active[bindingKey(b)] = installed{binding: b, plan: Plan{Policies: []CompiledPolicy{{Identity: PolicyIdentity{UID: p.identity.UID, Generation: p.identity.Generation}, Revision: "r"}}}}
	calls := 0
	var fail error
	c.options.KernelRuntime = func(section string) error {
		calls++
		if section != "privilege" {
			t.Fatalf("section %q", section)
		}
		return fail
	}
	if r := c.report(p, nil); r.Status.Conditions[0].Status != metav1.ConditionTrue || r.Status.AppliedGeneration == 0 {
		t.Fatalf("ftrace on: %+v", r.Status)
	}
	fail = &EnforcementUnavailableError{Section: "privilege", Reason: "FtraceDisabled", Detail: "kernel check ftrace: ftrace_enabled is 0"}
	r := c.report(p, nil)
	ready := r.Status.Conditions[0]
	if ready.Status != metav1.ConditionFalse || ready.Reason != "FtraceDisabled" || !strings.Contains(ready.Message, "unprotected") || r.Status.Tier != "none" || r.Status.AppliedGeneration != 0 || !r.Status.Stale {
		t.Fatalf("ftrace off: %s %d %v %+v", r.Status.Tier, r.Status.AppliedGeneration, r.Status.Stale, ready)
	}
	fail = nil
	if r := c.report(p, nil); r.Status.Conditions[0].Status != metav1.ConditionTrue || calls != 3 {
		t.Fatalf("ftrace back on, checked at every write: calls=%d %+v", calls, r.Status.Conditions[0])
	}
	// A policy without a loaded section is not this check's to judge.
	execOnly := parseTypedPolicy(t, policy("exec", "ns"))
	c.report(execOnly, nil)
	if calls != 3 {
		t.Fatal("an exec-only policy runs no section kernel check")
	}
}

type helperReporter struct {
	fakeBackend
	plans  []Plan
	exempt uint64
	err    error
}

func (h *helperReporter) RuntimeHelperStatus() (bool, []Plan, uint64, error) {
	return true, h.plans, h.exempt, h.err
}

// A policy whose pod bindings carry the operator-enabled runtime helper
// exemption reports it, with the exempted execs; an unreadable count is
// Unknown.
func TestRuntimeHelperExemptionInStatus(t *testing.T) {
	c, _, _, _ := setup(t)
	pol := policy("policy", "ns")
	pol.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, pol)
	r := &helperReporter{fakeBackend: fakeBackend{plans: map[string]Plan{}}, plans: []Plan{{Policies: []CompiledPolicy{{Identity: p.identity}}}}, exempt: 3}
	c.backend = r
	find := func() *metav1.Condition {
		for _, cond := range c.report(p, nil).Status.Conditions {
			if cond.Type == "RuntimeHelperExemption" {
				return &cond
			}
		}
		return nil
	}
	if cond := find(); cond == nil || cond.Status != metav1.ConditionTrue || !strings.Contains(cond.Message, "ExemptExecs=3") || !strings.Contains(cond.Message, "1 pod bindings") {
		t.Fatalf("exemption condition: %+v", cond)
	}
	r.err = errors.New("witness unreadable")
	if cond := find(); cond == nil || cond.Status != metav1.ConditionUnknown || cond.Reason != "WitnessUnknown" {
		t.Fatalf("unknown count: %+v", cond)
	}
}

// Exec failing after the privilege removal leaves a binding that runs neither
// plan: its old revision must not attest.
func TestSectionBackendPartialRemovalDoesNotAttest(t *testing.T) {
	exec := &fakeBackend{plans: map[string]Plan{}}
	privilege := &fakeBackend{plans: map[string]Plan{}}
	s, _ := NewSectionBackend(exec, privilege, nil)
	b := Binding{ContainerID: "c"}
	execPolicy := CompiledPolicy{Revision: "e", Exec: api.ExecSection{Default: api.ActionDeny}}
	privPolicy := CompiledPolicy{Revision: "p", Privilege: privilegeSection(api.ActionAllow)}
	if _, err := s.Replace(context.Background(), b, sectionPlan("r1", execPolicy, privPolicy)); err != nil {
		t.Fatal(err)
	}
	exec.fail = true
	execPolicy.Revision = "e2"
	execPolicy.Exec.Default = api.ActionAllow
	if r, err := s.Replace(context.Background(), b, sectionPlan("r2", execPolicy)); err == nil || r.Committed || !r.ProtectionUnconfirmed {
		t.Fatalf("exec failure after the removal: %+v %v", r, err)
	}
	if err := s.Attest(context.Background(), b, "r1"); err == nil {
		t.Fatal("the old revision must not attest after a partial removal")
	}
}

// conditionReasonSyntax is the API server's metav1.Condition reason syntax.
var conditionReasonSyntax = regexp.MustCompile(`^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$`)

func TestBoundConditionReason(t *testing.T) {
	long := strings.Repeat("A", 60)
	for _, tc := range []struct {
		name, in, want string
		cut            bool
	}{
		{"single", "Reconciled", "Reconciled", false},
		{"list", "FailClosedRecent,WitnessUnknown", "FailClosedRecent,WitnessUnknown", false},
		{"leading empty item", ",VerdictEventLoss", "VerdictEventLoss", true},
		{"empty items", "A,,B,", "A,B", true},
		{"empty", "", "Unknown", true},
		{"malformed items", "Good,bad-item,1st,Also_Good", "Good,Also_Good", true},
		{"exactly at the bound", strings.Repeat("B", api.MaxStatusConditionKeyLength), strings.Repeat("B", api.MaxStatusConditionKeyLength), false},
		{"over the bound", strings.Repeat("B", api.MaxStatusConditionKeyLength+1), "Unknown", true},
		{"long first item and more", strings.Repeat("B", 127) + ",C", "More", true},
		{"fits", long + "," + long, long + "," + long, false},
		{"whole items dropped", long + "," + long + "," + long, long + "," + long + ",More", true},
		{"first item fits", strings.Repeat("C", 125) + ",D", strings.Repeat("C", 125) + ",D", false},
		{"first item and More", strings.Repeat("C", 120) + ",DDDDDDDDDD", strings.Repeat("C", 120) + ",More", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, cut := BoundConditionReason(tc.in)
			if got != tc.want || cut != tc.cut {
				t.Fatalf("got %q cut %v, want %q %v", got, cut, tc.want, tc.cut)
			}
			if len(got) > api.MaxStatusConditionKeyLength || !conditionReasonSyntax.MatchString(got) {
				t.Fatalf("out of schema: %q", got)
			}
		})
	}
	// Many reasons: whole items only, then More.
	var many []string
	for i := range 40 {
		many = append(many, fmt.Sprintf("Reason%02d", i))
	}
	got, cut := BoundConditionReason(strings.Join(many, ","))
	if !cut || len(got) > api.MaxStatusConditionKeyLength || !strings.HasSuffix(got, ",More") || !conditionReasonSyntax.MatchString(got) {
		t.Fatalf("many reasons %q", got)
	}
	for item := range strings.SplitSeq(strings.TrimSuffix(got, ",More"), ",") {
		if !slices.Contains(many, item) {
			t.Fatalf("cut item %q", item)
		}
	}
}

// The writer fits every condition into the schema and marks the status
// truncated.
func TestDynamicStatusWriterBoundsConditions(t *testing.T) {
	ctx := context.Background()
	c, _, _, client := setup(t)
	r := c.report(parseTypedPolicy(t, policy("policy", "ns")), nil)
	r.Status.Conditions = append(r.Status.Conditions, metav1.Condition{Type: "Degraded", Status: metav1.ConditionTrue, Reason: strings.Repeat("Reason,", 40) + ",", Message: strings.Repeat("m", 3000)})
	if err := (DynamicStatusWriter{Client: client}).WriteStatus(ctx, r); err != nil {
		t.Fatal(err)
	}
	current, err := client.Resource(NodeStatusGVR).Namespace("ns").Get(ctx, r.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var stored api.SandboxPolicyNodeStatus
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(current.Object, &stored); err != nil {
		t.Fatal(err)
	}
	if !stored.Status.Truncated {
		t.Fatal("truncation not reported")
	}
	for _, condition := range stored.Status.Conditions {
		if len(condition.Reason) > api.MaxStatusConditionKeyLength || !conditionReasonSyntax.MatchString(condition.Reason) || utf8.RuneCountInString(condition.Message) > api.MaxStatusDiagnosticLength {
			t.Fatalf("out of schema: %+v", condition)
		}
	}
	if r.Status.Conditions[len(r.Status.Conditions)-1].Message != strings.Repeat("m", 3000) {
		t.Fatal("caller's report mutated")
	}
}
