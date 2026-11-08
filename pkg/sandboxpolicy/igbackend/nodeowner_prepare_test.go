package igbackend

import (
	"context"
	"fmt"
	"testing"

	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// policyPlans returns one plan per policy, as Controller.PrepareScheduled
// gives them for the active policies.
func policyPlans(policies ...sandboxpolicy.CompiledPolicy) []sandboxpolicy.Plan {
	var plans []sandboxpolicy.Plan
	for _, p := range policies {
		plans = append(plans, sandboxpolicy.Plan{Policies: []sandboxpolicy.CompiledPolicy{p}})
	}
	return plans
}

// The policy slots are prepared before any pod exists: the first instance
// already has them (one load, not an empty instance and then a replacement), a
// new policy adds its slot with one replacement, and a removed policy is
// dropped at the next replacement. Prepared slots are not "in use".
func TestPreparePolicySlotsBeforePods(t *testing.T) {
	e := &fakeNetworkEngine{}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	p1, p2 := netPolicy("p1", "allow", denyTestNet), netPolicy("p2", "deny")
	if err := b.Prepare(ctx, policyPlans(p1, p2)); err != nil || len(e.instances) != 1 || len(e.configs[0].Policy.Slots) != 2 {
		t.Fatalf("first start: %v instances=%d", err, len(e.instances))
	}
	if err := b.Prepare(ctx, policyPlans(p1, p2)); err != nil || len(e.instances) != 1 {
		t.Fatalf("same policies: %v instances=%d", err, len(e.instances))
	}
	// A new policy: one replacement, before any pod.
	p3 := netPolicy("p3", "allow", netpolicy.Rule{Name: "r3", Action: "deny", CIDRs: []string{"198.51.100.0/24"}})
	if err := b.Prepare(ctx, policyPlans(p1, p2, p3)); err != nil || len(e.instances) != 2 || len(e.configs[1].Policy.Slots) != 3 || e.instances[0].stops != 1 {
		t.Fatalf("new policy: %v instances=%d", err, len(e.instances))
	}
	// A removed policy leaves the prepared set at once and its slot at the
	// next replacement; it is not kept as a slot in use.
	if err := b.Prepare(ctx, policyPlans(p1, p3)); err != nil || len(e.instances) != 2 || len(b.prepared) != 2 {
		t.Fatalf("removed policy: %v instances=%d prepared=%d", err, len(e.instances), len(b.prepared))
	}
	p4 := netPolicy("p4", "deny")
	if err := b.Prepare(ctx, policyPlans(p1, p3, p4)); err != nil || len(e.instances) != 3 || len(e.configs[2].Policy.Slots) != 3 {
		t.Fatalf("next replacement: %v instances=%d", err, len(e.instances))
	}
	key2, _ := NetworkCombination(privPlan("", p2))
	if _, ok := b.slots[key2]; ok {
		t.Fatal("the removed policy's slot must be dropped at the next replacement")
	}
	// ClearPrepared (the section became inactive) still never starts one.
	if err := b.ClearPrepared(ctx); err != nil || len(e.instances) != 3 || len(b.prepared) != 0 {
		t.Fatalf("clear: %v instances=%d", err, len(e.instances))
	}
}

// A pod matched by one policy finds the policy slot: its pod binding and its
// container binding are live map writes. A pod matched by two policies needs
// their combined slot, which only the pod plan prepares (one replacement).
func TestPreparePolicySlotsBindPods(t *testing.T) {
	e := &fakeNetworkEngine{}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	p1, p2 := netPolicy("p1", "allow", denyTestNet), netPolicy("p2", "deny")
	if err := b.Prepare(ctx, policyPlans(p1, p2)); err != nil || len(e.instances) != 1 {
		t.Fatal(err)
	}
	// One policy: the pod plan has the policy slot's combination.
	one := privPlan("r1", p1)
	if err := b.Prepare(ctx, append([]sandboxpolicy.Plan{one}, policyPlans(p1, p2)...)); err != nil || len(e.instances) != 1 {
		t.Fatalf("pod with one policy: %v instances=%d", err, len(e.instances))
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, one)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[0].bound[100]; !ok || len(e.instances) != 1 {
		t.Fatal("the pod must bind live to the policy slot")
	}
	if _, err := b.Replace(ctx, privBinding(1), one); err != nil || len(e.instances) != 1 || b.Stats().Prepared != 1 || b.Stats().Replaced != 0 {
		t.Fatalf("container bind: %v instances=%d stats=%+v", err, len(e.instances), b.Stats())
	}
	// Two policies: their combination is not prepared by the policy plans.
	two := privPlan("r2", p1, p2)
	if err := b.Prepare(ctx, append([]sandboxpolicy.Plan{one, two}, policyPlans(p1, p2)...)); err != nil || len(e.instances) != 2 {
		t.Fatalf("pod with two policies: %v instances=%d", err, len(e.instances))
	}
	if n := len(e.configs[1].Policy.Slots); n != 3 {
		t.Fatalf("slots %d, want p1, p2 and p1+p2", n)
	}
}

// When the slots do not all fit, Prepare prepares what fits, in order (pod
// plans first), keeps the slots in use, and does not fail. A repeat does not
// reload the gadget.
func TestPreparePolicySlotsLimit(t *testing.T) {
	e := &fakeNetworkEngine{}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	inUse := privPlan("r0", netPolicy("in-use", "deny"))
	if _, err := b.Replace(ctx, privBinding(1), inUse); err != nil {
		t.Fatal(err)
	}
	pod := privPlan("r1", netPolicy("x1", "deny"), netPolicy("x2", "deny"))
	plans := []sandboxpolicy.Plan{pod}
	for i := 0; i < netpolicy.KernelMaxSlots; i++ {
		plans = append(plans, policyPlans(netPolicy(fmt.Sprintf("p%02d", i), "deny"))...)
	}
	if err := b.Prepare(ctx, plans); err != nil || len(e.instances) != 2 {
		t.Fatalf("prepare: %v instances=%d", err, len(e.instances))
	}
	if n := len(e.configs[1].Policy.Slots); n != netpolicy.KernelMaxSlots || b.unfit != 2 {
		t.Fatalf("slots=%d unfit=%d, want the limit and 2 left out", n, b.unfit)
	}
	podKey, _ := NetworkCombination(pod)
	inUseKey, _ := NetworkCombination(inUse)
	if _, ok := b.slots[podKey]; !ok {
		t.Fatal("the pod plan comes first and must be prepared")
	}
	if _, ok := b.slots[inUseKey]; !ok || e.instances[1].bound[1] != b.slots[inUseKey] {
		t.Fatal("the slot in use must be kept")
	}
	if err := b.Prepare(ctx, plans); err != nil || len(e.instances) != 2 {
		t.Fatalf("repeat: %v instances=%d", err, len(e.instances))
	}
}

// The privilege section gets the same policy slots (generic node owner).
func TestPreparePolicySlotsPrivilege(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	p1, p2 := privPolicy("p1", api.ActionAllow, denyMount), privPolicy("p2", api.ActionDeny)
	if err := b.Prepare(ctx, policyPlans(p1, p2)); err != nil || len(e.instances) != 1 || e.configs[0].Policy.Slots != 2 {
		t.Fatalf("first start: %v instances=%d", err, len(e.instances))
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, privPlan("r1", p2))}); err != nil || len(e.instances) != 1 {
		t.Fatal(err)
	}
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", p2)); err != nil || len(e.instances) != 1 || b.Stats().Prepared != 1 {
		t.Fatalf("container bind: %v instances=%d", err, len(e.instances))
	}
	if e.instances[0].bound[100] != e.instances[0].bound[1] {
		t.Fatal("the pod and its container share the policy slot")
	}
}
