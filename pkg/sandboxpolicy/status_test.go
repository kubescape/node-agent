package sandboxpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

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

// On a kernel that is not qualified the privilege section enforces, but a
// privilege policy never reports Ready.
func TestUnqualifiedKernelIsNotReady(t *testing.T) {
	c, _, _, _ := setup(t)
	withPrivilege := policy("policy", "ns")
	withPrivilege.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, withPrivilege)
	sections, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}, nil)
	sections.SetPrivilegeUnqualified(&EnforcementUnavailableError{Section: "privilege", Reason: "PrivilegeKernelUnqualified", Detail: "kernel 6.17 is not qualified"})
	c.backend = sections
	if r := c.report(p, nil); r.Status.Conditions[0].Status != metav1.ConditionFalse || r.Status.Conditions[0].Reason != "PrivilegeKernelUnqualified" {
		t.Fatalf("unqualified kernel: %+v", r.Status.Conditions[0])
	}
	if _, err := sections.Replace(context.Background(), Binding{ContainerID: "c"}, sectionPlan("r", CompiledPolicy{Revision: "p", Privilege: privilegeSection(api.ActionDeny)})); err != nil {
		t.Fatalf("the privilege section still enforces: %v", err)
	}
}
