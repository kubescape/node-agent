package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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

// A faulted pod binding is a known loss: an unreadable witness next to it does
// not turn the report into Unknown.
func TestFaultedPodBindingIsNotWitnessUnknown(t *testing.T) {
	c, _, _, _ := setup(t)
	p := parseTypedPolicy(t, policy("policy", "ns"))
	p.identity.Generation = 3
	backend := &podReportingBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	backend.faulted = []Plan{{Policies: []CompiledPolicy{{Identity: PolicyIdentity{UID: p.identity.UID, Generation: 3}}}}}
	c.backend = backend
	failure := &protectionError{errors.Join(fmt.Errorf("%w: privilege slot 0 faults: EIO", ErrWitnessUnknown), errProtectionUnconfirmed)}
	r := c.report(p, failure)
	if r.Status.Conditions[0].Status != metav1.ConditionFalse || r.Status.Conditions[0].Reason != "ProtectionUnconfirmed" {
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
	// No binding failed to apply it, so the message names no failed count.
	if message := r.Status.Conditions[0].Message; message != "Desired revision applied on 1 binding(s); another step failed; see error" {
		t.Fatalf("message %q", message)
	}
	if active := r.Status.Conditions[1]; active.Type != "ActiveRevision" || active.Message != "generation=3 scope=subtree" {
		t.Fatalf("active revision %+v", active)
	}
}

// A partial apply names how many bindings enforce the desired generation and
// how many failed to apply it.
func TestPartialFailureCountsBindings(t *testing.T) {
	ctx := context.Background()
	c, b, w, _ := setup(t, policy("policy", "ns"))
	if err := c.InitialSync(ctx); err != nil {
		t.Fatal(err)
	}
	var bindings []Binding
	for i, id := range []string{"a", "b", "c"} {
		next := binding()
		next.ContainerID, next.CgroupID = id, uint64(20+i)
		bindings = append(bindings, next)
	}
	b.failKeys = map[string]bool{bindingKey(bindings[2]): true}
	if err := c.SetBindings(ctx, bindings); err == nil {
		t.Fatal("a failed binding is reported")
	}
	r := w.reports["policy"]
	if r.Status.Stale || r.Status.AppliedGeneration != 1 || r.Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatalf("status %+v", r.Status)
	}
	if message := r.Status.Conditions[0].Message; !strings.Contains(message, "applied on 2 binding(s), failed on 1") {
		t.Fatalf("message %q", message)
	}
	// The next reconcile counts again; it does not add to the last one.
	if err := c.Reconcile(ctx); err == nil {
		t.Fatal("a failed binding is reported")
	}
	if message := w.reports["policy"].Status.Conditions[0].Message; !strings.Contains(message, "applied on 2 binding(s), failed on 1") {
		t.Fatalf("message after retry %q", message)
	}
	b.failKeys = nil
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if ready := w.reports["policy"].Status.Conditions[0]; ready.Status != metav1.ConditionTrue {
		t.Fatalf("ready %+v", ready)
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

// A Strict binding refused because the container holds io_uring rings
// reports NotReady with the typed reason IoUringHeld (review 7).
func TestIoUringHeldRefusalIsReported(t *testing.T) {
	c, _, _, _ := setup(t)
	withPrivilege := policy("policy", "ns")
	withPrivilege.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, withPrivilege)
	refused := errors.Join(errors.New("bind failed"), &BindingRefusedError{Section: "privilege", Reason: "IoUringHeld", Detail: "container c holds io_uring rings opened before its Strict binding"})
	r := c.report(p, refused)
	if ready := r.Status.Conditions[0]; ready.Status != metav1.ConditionFalse || ready.Reason != "IoUringHeld" || !strings.Contains(ready.Message, "io_uring") {
		t.Fatalf("ready %+v", ready)
	}
}

// An Audit binding whose container holds io_uring rings opened before it
// binds, and the policy reports it: Degraded, reason IoUringHeld.
func TestIoUringHeldAuditIsReported(t *testing.T) {
	c, _, _, _ := setup(t)
	withPrivilege := policy("policy", "ns")
	withPrivilege.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, withPrivilege)
	b := binding()
	c.active[bindingKey(b)] = installed{binding: b, ioUringHeld: true, plan: Plan{Policies: []CompiledPolicy{{Identity: PolicyIdentity{UID: p.identity.UID, Generation: p.identity.Generation}, Revision: "r"}}}}
	r := c.report(p, nil)
	for _, cond := range r.Status.Conditions {
		if cond.Type == "Degraded" {
			if cond.Status != metav1.ConditionTrue || cond.Reason != "IoUringHeld" || !strings.Contains(cond.Message, "io_uring") {
				t.Fatalf("degraded %+v", cond)
			}
			return
		}
	}
	t.Fatalf("no Degraded condition: %+v", r.Status.Conditions)
}

// On a kernel outside the section's list the privilege section is not loaded:
// a privilege policy is Ready False with the kernel check's reason, tier none,
// and nothing binds its privilege section.
func TestKernelRefusedSectionIsNotLoaded(t *testing.T) {
	c, _, _, _ := setup(t)
	withPrivilege := policy("policy", "ns")
	withPrivilege.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, withPrivilege)
	sections, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, nil, &EnforcementUnavailableError{Section: "privilege", Reason: "PrivilegeKernelUnqualified", Detail: "kernel check btf: unreadable BTF"})
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

// Hooks a loaded section's canary does not prove are in its policies'
// status: the ones no node can prove in the Ready message, the ones not
// proven on this node as Degraded (<Section>HooksUnproven). Ready stays
// True: the section enforces, part of it is not attested.
func TestHooksUnprovenInStatus(t *testing.T) {
	c, _, _, _ := setup(t)
	withPrivilege := policy("policy", "ns")
	withPrivilege.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, withPrivilege)
	sections, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, &fakeBackend{plans: map[string]Plan{}}, nil)
	c.backend = sections
	b := binding()
	c.active[bindingKey(b)] = installed{binding: b, plan: Plan{Policies: []CompiledPolicy{{Identity: PolicyIdentity{UID: p.identity.UID, Generation: p.identity.Generation}, Revision: "r"}}}}
	unproven := HooksUnproven{Always: map[string]string{"kernel_read_file": "no harmless trigger"}}
	c.options.HooksUnproven = func(section string) HooksUnproven {
		if section != SectionPrivilege {
			t.Fatalf("section %q", section)
		}
		return unproven
	}
	degraded := func(r *api.SandboxPolicyNodeStatus) *metav1.Condition {
		for i := range r.Status.Conditions {
			if r.Status.Conditions[i].Type == "Degraded" {
				return &r.Status.Conditions[i]
			}
		}
		return nil
	}
	r := c.report(p, nil)
	ready := r.Status.Conditions[0]
	if ready.Status != metav1.ConditionTrue || !strings.Contains(ready.Message, "privilege: kernel_read_file (no harmless trigger)") {
		t.Fatalf("always unproven: %+v", ready)
	}
	if d := degraded(r); d != nil {
		t.Fatalf("a hook no node proves made the policy Degraded: %+v", d)
	}
	unproven.Node = map[string]string{"cred_alloc_blank": "its call was refused (EPERM)"}
	r = c.report(p, nil)
	d := degraded(r)
	if r.Status.Conditions[0].Status != metav1.ConditionTrue || d == nil || d.Status != metav1.ConditionTrue || d.Reason != "PrivilegeHooksUnproven" ||
		!strings.Contains(d.Message, "cred_alloc_blank (its call was refused (EPERM))") {
		t.Fatalf("unproven on this node: %+v %+v", r.Status.Conditions[0], d)
	}
	// Not consulted for a policy that is off.
	off := p
	off.spec.Mode = api.ModeOff
	c.options.HooksUnproven = func(string) HooksUnproven {
		t.Fatal("no report expected")
		return HooksUnproven{}
	}
	c.report(off, nil)
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
	// A network-only policy runs the check for the network section.
	sections.WithNetwork(&fakeBackend{plans: map[string]Plan{}}, nil)
	netOnly := policy("net", "ns")
	netOnly.Spec.Network = netSpec(api.ActionDeny).Network
	fail = &EnforcementUnavailableError{Section: "network", Reason: "FtraceDisabled", Detail: "kernel check ftrace: ftrace_enabled is 0"}
	c.options.KernelRuntime = func(section string) error {
		calls++
		if section != SectionNetwork {
			t.Fatalf("section %q", section)
		}
		return fail
	}
	if r := c.report(parseTypedPolicy(t, netOnly), nil); r.Status.Conditions[0].Reason != "FtraceDisabled" || r.Status.Tier != "none" || calls != 4 {
		t.Fatalf("network ftrace off: calls=%d %s %+v", calls, r.Status.Tier, r.Status.Conditions[0])
	}
	// Privilege refused, network loaded: the network check still runs, and
	// names the cause.
	both := policy("both", "ns")
	both.Spec.Privilege = privilegeSection(api.ActionDeny)
	both.Spec.Network = netSpec(api.ActionDeny).Network
	refusedSections, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, nil, &EnforcementUnavailableError{Section: "privilege", Reason: "PrivilegeKernelUnqualified", Detail: "kernel check btf"})
	refusedSections.WithNetwork(&fakeBackend{plans: map[string]Plan{}}, nil)
	c.backend = refusedSections
	if r := c.report(parseTypedPolicy(t, both), nil); r.Status.Conditions[0].Reason != "FtraceDisabled" || calls != 5 {
		t.Fatalf("privilege refused, network ftrace off: calls=%d %+v", calls, r.Status.Conditions[0])
	}
	c.backend = sections
	// A file-only policy runs the check for the file section (it also
	// covers the root barrier, which loads with it).
	sections.WithFile(&fakeBackend{plans: map[string]Plan{}}, nil)
	fileOnly := policy("file", "ns")
	fileOnly.Spec.File = fileSpec(api.ActionAllow).File
	c.options.KernelRuntime = func(section string) error {
		calls++
		if section != SectionFile {
			t.Fatalf("section %q", section)
		}
		return fail
	}
	if r := c.report(parseTypedPolicy(t, fileOnly), nil); r.Status.Conditions[0].Reason != "FtraceDisabled" || r.Status.Tier != "none" || r.Status.AppliedGeneration != 0 || !r.Status.Stale || calls != 6 {
		t.Fatalf("file ftrace off: calls=%d %+v", calls, r.Status)
	}
	// A file section refused at start is not loaded: its own reason, and
	// no runtime check for it.
	fileRefused, _ := NewSectionBackend(&fakeBackend{plans: map[string]Plan{}}, nil, nil)
	fileRefused.WithFile(nil, &EnforcementUnavailableError{Section: "file", Reason: "FileKernelUnqualified", Detail: "kernel check release"})
	c.backend = fileRefused
	if r := c.report(parseTypedPolicy(t, fileOnly), nil); r.Status.Conditions[0].Reason != "FileKernelUnqualified" || r.Status.Tier != "none" || calls != 6 {
		t.Fatalf("file refused: calls=%d %s %+v", calls, r.Status.Tier, r.Status.Conditions[0])
	}
	c.backend = sections
	// A policy without a loaded section is not this check's to judge.
	execOnly := parseTypedPolicy(t, policy("exec", "ns"))
	c.report(execOnly, nil)
	if calls != 6 {
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
	if r, err := s.Replace(context.Background(), b, sectionPlan("r2", execPolicy)); err == nil || !r.Committed || !r.ProtectionUnconfirmed {
		t.Fatalf("exec failure after the removal: %+v %v", r, err)
	}
	if s.Attest(context.Background(), b, "r1") == nil || s.Attest(context.Background(), b, "r2") == nil {
		t.Fatal("neither revision may attest after a partial removal")
	}
}

type rateBackend struct {
	fakeBackend
	report RateReport
}

func (r *rateBackend) SampleRates(time.Time) {}
func (r *rateBackend) PolicyRates(types.UID, time.Time) (RateReport, bool) {
	return r.report, true
}

// The runtime reporting rule: Ready (NotReady, Unknown) and its own
// Degraded condition.
func TestStatusFollowsReportingRule(t *testing.T) {
	c, _, _, _ := setup(t)
	pol := policy("policy", "ns")
	pol.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, pol)
	r := &rateBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	c.backend = r
	for name, tc := range map[string]struct {
		report           RateReport
		ready            metav1.ConditionStatus
		reason, degraded string
	}{
		"clean":    {RateReport{}, metav1.ConditionTrue, "Reconciled", "False"},
		"degraded": {RateReport{Degraded: true, Message: "privilege: 1"}, metav1.ConditionTrue, "Reconciled", "True"},
		"rate":     {RateReport{Degraded: true, NotReady: true}, metav1.ConditionFalse, "FailClosedRate", "True"},
		"unknown":  {RateReport{Unknown: errors.New("unreadable"), Degraded: true}, metav1.ConditionUnknown, "WitnessUnknown", "Unknown"},
		// Lost verdicts degrade, never make the policy not ready.
		"suppressed": {RateReport{Suppressed: 5, SuppressedNote: "privilege 5"}, metav1.ConditionTrue, "Reconciled", "True"},
	} {
		r.report = tc.report
		conds := c.report(p, nil).Status.Conditions
		var degraded string
		for _, cond := range conds {
			if cond.Type == "Degraded" {
				degraded = string(cond.Status)
			}
		}
		if conds[0].Status != tc.ready || conds[0].Reason != tc.reason || degraded != tc.degraded {
			t.Errorf("%s: Ready %s/%s Degraded %q, want %s/%s %q", name, conds[0].Status, conds[0].Reason, degraded, tc.ready, tc.reason, tc.degraded)
		}
	}
}

type restartBackend struct {
	fakeBackend
	adopted []AdoptedSlot
	restart []SectionRestart
}

func (r *restartBackend) Adopted() []AdoptedSlot            { return r.adopted }
func (r *restartBackend) RestartSurvival() []SectionRestart { return r.restart }

// Restart survival in status: AdoptedLastGood names the revision the adopted
// state enforces; past the settle deadline the policy is Degraded; a pinned
// link that is gone makes it Unknown; RestartSurvival names what survives a
// restart (exec does not) and a failed pin.
func TestStatusRestartSurvival(t *testing.T) {
	c, _, _, _ := setup(t)
	pol := policy("policy", "ns")
	pol.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, pol)
	slot := AdoptedSlot{Section: SectionPrivilege, Slot: 5, Generation: 7, Digest: "d", Bindings: 1,
		Policies: []PolicyRevision{{Policy: p.identity, Revision: "r0"}}}
	r := &restartBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	c.backend = r
	find := func(conds []metav1.Condition, kind string) *metav1.Condition {
		for i := range conds {
			if conds[i].Type == kind {
				return &conds[i]
			}
		}
		return nil
	}
	r.adopted = []AdoptedSlot{slot}
	conds := c.report(p, nil).Status.Conditions
	if a := find(conds, "AdoptedLastGood"); a == nil || a.Reason != "RestartAdopted" || !strings.Contains(a.Message, "revision=r0 generation=7 digest=d") || conds[0].Reason != "Reconciled" {
		t.Fatalf("adopted: %+v", conds)
	}
	slot.Degraded = true
	r.adopted = []AdoptedSlot{slot}
	conds = c.report(p, nil).Status.Conditions
	if a, d := find(conds, "AdoptedLastGood"), find(conds, "Degraded"); a == nil || a.Reason != "SettleDeadlinePassed" || d == nil || d.Status != metav1.ConditionTrue || d.Reason != "SettleDeadlinePassed" || conds[0].Status != metav1.ConditionTrue {
		t.Fatalf("past the deadline: %+v", conds)
	}
	slot.LinkError = errors.New("pinned link gone")
	r.adopted = []AdoptedSlot{slot}
	conds = c.report(p, nil).Status.Conditions
	if a := find(conds, "AdoptedLastGood"); a == nil || a.Status != metav1.ConditionUnknown || conds[0].Status != metav1.ConditionUnknown {
		t.Fatalf("a missing pinned link: %+v", conds)
	}
	r.adopted = nil
	// Review 8, S5: True only when every section the policy uses survives.
	for _, tc := range []struct {
		name    string
		restart []SectionRestart
		status  metav1.ConditionStatus
		reason  string
	}{
		{"privilege pinned, exec never", []SectionRestart{{Section: SectionPrivilege, Pinned: true}, {Section: "exec", Err: errExecNotPinned}}, metav1.ConditionFalse, "PartlyPinned"},
		{"privilege not pinned yet", []SectionRestart{{Section: SectionPrivilege}, {Section: "exec", Err: errExecNotPinned}}, metav1.ConditionUnknown, "PinPending"},
		{"only a pending section", []SectionRestart{{Section: SectionPrivilege}}, metav1.ConditionUnknown, "PinPending"},
		{"only exec", []SectionRestart{{Section: "exec", Err: errExecNotPinned}}, metav1.ConditionFalse, "NotPinned"},
	} {
		r.restart = tc.restart
		if rs := find(c.report(p, nil).Status.Conditions, "RestartSurvival"); rs == nil || rs.Status != tc.status || rs.Reason != tc.reason {
			t.Fatalf("%s: %+v", tc.name, rs)
		}
	}
	r.restart = []SectionRestart{{Section: SectionPrivilege, Pinned: true}}
	noExec := p
	noExec.spec.Exec = nil
	if rs := find(c.report(noExec, nil).Status.Conditions, "RestartSurvival"); rs == nil || rs.Status != metav1.ConditionTrue || rs.Reason != "Pinned" || !strings.Contains(rs.Message, "privilege") {
		t.Fatalf("every used section pinned: %+v", rs)
	}
	r.restart = []SectionRestart{{Section: SectionPrivilege, Pinned: true}, {Section: "exec", Err: errExecNotPinned}}
	r.restart[0] = SectionRestart{Section: SectionPrivilege, Err: errors.New("bpffs full")}
	if rs := find(c.report(p, nil).Status.Conditions, "RestartSurvival"); rs == nil || rs.Status != metav1.ConditionFalse || rs.Reason != "PinFailed" {
		t.Fatalf("pin failed: %+v", rs)
	}
}

type restartRateBackend struct {
	restartBackend
	rates RateReport
}

func (r *restartRateBackend) SampleRates(time.Time) {}
func (r *restartRateBackend) PolicyRates(types.UID, time.Time) (RateReport, bool) {
	return r.rates, true
}

// Past the settle deadline, Degraded is True and keeps both messages: the
// deadline is the reason over suppressed verdicts and an unreadable counter;
// fail-closed checks stay the reason and the deadline note is added.
func TestStatusDeadlineAndRateDegraded(t *testing.T) {
	c, _, _, _ := setup(t)
	pol := policy("policy", "ns")
	pol.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, pol)
	r := &restartRateBackend{restartBackend: restartBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}}
	r.adopted = []AdoptedSlot{{Section: SectionPrivilege, Slot: 5, Generation: 7, Digest: "d", Bindings: 1, Degraded: true,
		Policies: []PolicyRevision{{Policy: p.identity, Revision: "r0"}}}}
	c.backend = r
	for _, tc := range []struct {
		name   string
		rates  RateReport
		reason string
		keep   string
	}{
		{"no rate finding", RateReport{}, "SettleDeadlinePassed", "settle deadline passed"},
		{"suppressed verdicts", RateReport{Suppressed: 9, SuppressedNote: "privilege 9"}, "SettleDeadlinePassed", "privilege 9"},
		{"unreadable counter", RateReport{Unknown: errors.New("counter read failed")}, "SettleDeadlinePassed", "counter read failed"},
		{"fail-closed checks", RateReport{Degraded: true, Message: "privilege: 1"}, "FailClosedRecent", "settle deadline passed"},
	} {
		r.rates = tc.rates
		var degraded *metav1.Condition
		for _, cond := range c.report(p, nil).Status.Conditions {
			if cond.Type == "Degraded" {
				degraded = &cond
			}
		}
		if degraded == nil || degraded.Status != metav1.ConditionTrue || degraded.Reason != tc.reason || !strings.Contains(degraded.Message, tc.keep) {
			t.Fatalf("%s: degraded %+v", tc.name, degraded)
		}
	}
}

// Every degraded entry the status writes has a status CRD effective value:
// the CRD refuses any other, and then every status write of the policy fails
// (pen-test pilot). An execMap-only enforce deny has no entry; the Ready
// message names it.
func TestStatusDegradedEffectiveIsCRDValue(t *testing.T) {
	c, _, _, _ := setup(t)
	spec := fileSpec(api.ActionAllow,
		fileRule("wx", api.ActionDeny, api.FileTarget{Access: []string{"execMap"}}),
		fileRule("hooks", api.ActionDeny, api.FileTarget{Access: []string{"write", "execMap"}, PathTarget: api.PathTarget{Path: []string{"/x/**"}}}))
	pol := policy("policy", "ns")
	pol.Spec.Mode, pol.Spec.File = spec.Mode, spec.File
	p := parseTypedPolicy(t, pol)
	if c.filePlans == nil {
		c.filePlans = map[types.UID]*FilePlan{}
	}
	c.filePlans[p.identity.UID] = translateFile(t, spec, nil)
	st := c.report(p, nil).Status
	var rules []string
	for _, d := range st.Degraded {
		rules = append(rules, d.Rule)
		if !slices.Contains([]string{"audit", "enforce", "tripwire"}, d.Effective) {
			t.Fatalf("degraded %s: effective %q is not a status CRD value", d.Rule, d.Effective)
		}
	}
	if !slices.Equal(rules, []string{"hooks"}) {
		t.Fatalf("degraded %v, want only hooks", rules)
	}
	if ready := st.Conditions[0]; ready.Reason != "NotEnforceable" || !strings.Contains(ready.Message, "execMap deny is not enforced at all") {
		t.Fatalf("ready %+v", ready)
	}
}

// Denies with no verdict event: Degraded VerdictsSuppressed, with the count
// and the sections, said to be node-wide per section; with fail-closed checks
// in the window the stronger reason stays and the note is added.
func TestDegradedVerdictsSuppressed(t *testing.T) {
	c := degradedCondition(RateReport{Suppressed: 507, SuppressedNote: "privilege 500, file 7"})
	if c.Status != metav1.ConditionTrue || c.Reason != "VerdictsSuppressed" ||
		!strings.Contains(c.Message, "507") || !strings.Contains(c.Message, "privilege 500, file 7") ||
		!strings.Contains(c.Message, "node-wide per section, not per policy") || !strings.Contains(c.Message, "enforcement unchanged") {
		t.Fatalf("suppressed: %+v", c)
	}
	c = degradedCondition(RateReport{Degraded: true, Message: "privilege: 1", Suppressed: 3, SuppressedNote: "network 3"})
	if c.Reason != "FailClosedRecent" || !strings.Contains(c.Message, "network 3") {
		t.Fatalf("fail-closed and suppressed: %+v", c)
	}
	if c := degradedCondition(RateReport{}); c.Status != metav1.ConditionFalse || strings.Contains(c.Message, "no verdict") {
		t.Fatalf("clean: %+v", c)
	}
	// An unreadable verdict counter: the loss is unknown, never zero.
	c = degradedCondition(RateReport{SuppressedUnknown: "file"})
	if c.Status != metav1.ConditionUnknown || c.Reason != "VerdictLossUnknown" || !strings.Contains(c.Message, "cannot be counted") || !strings.Contains(c.Message, "file") {
		t.Fatalf("loss unknown: %+v", c)
	}
	c = degradedCondition(RateReport{Suppressed: 4, SuppressedNote: "network 4", SuppressedUnknown: "file"})
	if c.Reason != "VerdictsSuppressed" || !strings.Contains(c.Message, "network 4") || !strings.Contains(c.Message, "cannot be counted") {
		t.Fatalf("loss and unknown loss: %+v", c)
	}
}

// The CRD allows 8 conditions: a longer list keeps the most important ones,
// in order, and marks the report truncated.
func TestCapConditions(t *testing.T) {
	var conds []metav1.Condition
	for _, typ := range []string{"Ready", "ActiveRevision", "NetworkNotEnforced", "FileNotEnforced", "IdentityNotEnforced", "AdoptedLastGood", "RuntimeHelperExemption", "RestartSurvival", "Degraded"} {
		conds = append(conds, metav1.Condition{Type: typ})
	}
	got, cut := capConditions(conds)
	if !cut || len(got) != api.MaxStatusConditions || got[0].Type != "Ready" {
		t.Fatalf("cap: %v %+v", cut, got)
	}
	for _, c := range got {
		if c.Type == "ActiveRevision" {
			t.Fatalf("the lowest priority goes first: %+v", got)
		}
	}
	if same, cut := capConditions(conds[:3]); cut || len(same) != 3 {
		t.Fatal("a short list stays as it is")
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

func TestStatusAppliedGeneration(t *testing.T) {
	c, _, _, _ := setup(t)
	p := parseTypedPolicy(t, policy("policy", "ns"))
	p.identity.Generation = 3
	bind := func(key string, generation int64, unconfirmed bool) {
		identity := p.identity
		identity.Generation = generation
		c.active[key] = installed{plan: Plan{Policies: []CompiledPolicy{{Identity: identity, Revision: fmt.Sprintf("r%d", generation)}}}, protectionUnconfirmed: unconfirmed}
	}
	other := p.identity
	other.UID, other.Generation = "other", 1

	if got := c.report(p, nil).Status.AppliedGeneration; got != 0 {
		t.Fatalf("no bindings: appliedGeneration %d, want absent", got)
	}
	c.active["other"] = installed{plan: Plan{Policies: []CompiledPolicy{{Identity: other, Revision: "o1"}}}}
	if got := c.report(p, nil).Status.AppliedGeneration; got != 0 {
		t.Fatalf("other policy's binding counted: appliedGeneration %d", got)
	}
	bind("a", 3, false)
	if got := c.report(p, nil).Status.AppliedGeneration; got != 3 {
		t.Fatalf("current binding: appliedGeneration %d, want 3", got)
	}
	bind("b", 2, false)
	if got := c.report(p, errors.New("rejected")).Status.AppliedGeneration; got != 2 {
		t.Fatalf("mixed bindings: appliedGeneration %d, want the oldest (2)", got)
	}
	bind("c", 1, true)
	if got := c.report(p, nil).Status.AppliedGeneration; got != 2 {
		t.Fatalf("unconfirmed binding counted: appliedGeneration %d, want 2", got)
	}
	delete(c.active, "a")
	delete(c.active, "b")
	if got := c.report(p, nil).Status.AppliedGeneration; got != 0 {
		t.Fatalf("only unconfirmed bindings: appliedGeneration %d, want absent", got)
	}
	delete(c.active, "c")
	bind("d", 4, false)
	if r := c.report(p, nil); r.Status.AppliedGeneration != 0 || r.Status.ObservedGeneration != 3 {
		t.Fatalf("installed generation above observed must be omitted (admission rejects it): %+v", r.Status)
	}
}

// The CRD admits appliedGeneration only if it is absent or at most
// observedGeneration; zero must reach the API server as an absent field, and a
// heartbeat must remove a previously stored value.
func TestDynamicStatusWriterOmitsZeroAppliedGeneration(t *testing.T) {
	ctx := context.Background()
	c, _, _, client := setup(t)
	r := c.report(parseTypedPolicy(t, policy("policy", "ns")), nil)
	writer := DynamicStatusWriter{Client: client}
	stored := func() map[string]any {
		t.Helper()
		current, err := client.Resource(NodeStatusGVR).Namespace("ns").Get(ctx, r.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		status, _, _ := unstructured.NestedMap(current.Object, "status")
		return status
	}
	r.Status.AppliedGeneration = 1
	if err := writer.WriteStatus(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, ok := stored()["appliedGeneration"]; !ok || got != int64(1) {
		t.Fatalf("appliedGeneration not stored: %v", got)
	}
	r.Status.AppliedGeneration = 0
	if err := writer.WriteStatus(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, ok := stored()["appliedGeneration"]; ok {
		t.Fatalf("zero appliedGeneration stored as %v, want absent", got)
	}
}

func TestNotReadyNamesIdentityDefaultDeny(t *testing.T) {
	reason, message := notReady(nil, nil, "NotEnforceable")
	if reason != "NotEnforceable" || !strings.Contains(message, "identity enforce default deny") {
		t.Fatalf("reason %q message %q", reason, message)
	}
	// A section reason comes first.
	if reason, _ := notReady(nil, &NetworkReport{NotReady: "ClassUnresolved"}, "NotEnforceable"); reason != "ClassUnresolved" {
		t.Fatalf("reason %q", reason)
	}
}

// Review 8, S1: adopted bindings whose policies are all gone from the listed
// configuration are counted for the node (no policy status carries them).
func TestAdoptedWithoutPolicy(t *testing.T) {
	c, _, _, _ := setup(t)
	r := &restartBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	c.backend = r
	if _, ok := c.AdoptedWithoutPolicy(); ok {
		t.Fatal("no configuration listed yet: the count is not known")
	}
	versions := map[types.UID]string{"live": "1"}
	c.configurationVersions.Store(&versions)
	r.adopted = []AdoptedSlot{
		{Section: SectionNetwork, Slot: 1, Bindings: 2, Policies: []PolicyRevision{{Policy: PolicyIdentity{UID: "gone"}}}},
		{Section: SectionNetwork, Slot: 2, Bindings: 3, Policies: []PolicyRevision{{Policy: PolicyIdentity{UID: "gone"}}, {Policy: PolicyIdentity{UID: "live"}}}},
		{Section: SectionFile, Slot: 1, Bindings: 4}, // no manifest: policies unknown
	}
	counts, ok := c.AdoptedWithoutPolicy()
	if !ok || counts[SectionNetwork] != 2 || counts[SectionFile] != 0 {
		t.Fatalf("counts %v %v", counts, ok)
	}
}

// Review 8, S3: a pinned set that could not be read is kept; its policies are
// not known, so every policy of its section reports it (Unknown).
func TestStatusUnreadablePinnedSet(t *testing.T) {
	c, _, _, _ := setup(t)
	pol := policy("policy", "ns")
	pol.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, pol)
	r := &restartBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	c.backend = r
	r.adopted = []AdoptedSlot{{Section: SectionPrivilege, Unreadable: true, LinkError: errors.New("set-1 not validated: EIO")}}
	for _, cond := range c.report(p, nil).Status.Conditions {
		if cond.Type == "AdoptedLastGood" {
			if cond.Status != metav1.ConditionUnknown || !strings.Contains(cond.Message, "policies are not known") {
				t.Fatalf("unreadable set: %+v", cond)
			}
			r.adopted[0].Section = SectionNetwork
			for _, cond := range c.report(p, nil).Status.Conditions {
				if cond.Type == "AdoptedLastGood" {
					t.Fatalf("a set of another section must not show: %+v", cond)
				}
			}
			return
		}
	}
	t.Fatal("no AdoptedLastGood for an unreadable set")
}

// A slot with no manifest policies and an ordinary link error is not an
// unreadable set: it shows on no policy as "could not be read".
func TestStatusSlotWithoutPoliciesIsNotUnreadable(t *testing.T) {
	c, _, _, _ := setup(t)
	pol := policy("policy", "ns")
	pol.Spec.Privilege = privilegeSection(api.ActionDeny)
	p := parseTypedPolicy(t, pol)
	r := &restartBackend{fakeBackend: fakeBackend{plans: map[string]Plan{}}}
	c.backend = r
	r.adopted = []AdoptedSlot{{Section: SectionPrivilege, Slot: 3, Bindings: 1, LinkError: errors.New("pinned link gone")}}
	for _, cond := range c.report(p, nil).Status.Conditions {
		if cond.Type == "AdoptedLastGood" {
			t.Fatalf("a slot of no known policy must not show: %+v", cond)
		}
	}
}
