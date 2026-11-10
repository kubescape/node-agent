package igbackend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/policy"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

type fakePrivilegeInstance struct {
	readyErr, stopErr error
	stops             int
	bound             map[uint64]uint32
	faults            map[uint32]uint64
	// published holds the compiled policy of each slot published in place;
	// freed the slots freed (unavailable until clearFreed).
	published  map[uint32]any
	freed      map[uint32]bool
	publishErr error
	freeErr    error
	heals      int
	// capacity > 0 limits the slots the instance has.
	capacity int
}

func (i *fakePrivilegeInstance) Publish(slot uint32, compiled any) error {
	if i.publishErr != nil {
		return i.publishErr
	}
	if i.published == nil {
		i.published = map[uint32]any{}
	}
	i.published[slot] = compiled
	return nil
}
func (i *fakePrivilegeInstance) Free(slot uint32) error {
	if i.freeErr != nil {
		return i.freeErr
	}
	for _, s := range i.bound {
		if s == slot {
			return fmt.Errorf("slot %d is still bound", slot)
		}
	}
	if i.freed == nil {
		i.freed = map[uint32]bool{}
	}
	i.freed[slot] = true
	delete(i.published, slot)
	return nil
}
func (i *fakePrivilegeInstance) Available(slot uint32) bool {
	if i.capacity > 0 && int(slot) >= i.capacity {
		return false
	}
	_, used := i.published[slot]
	return !used && !i.freed[slot]
}
func (i *fakePrivilegeInstance) Heal(slot uint32) error {
	i.heals++
	delete(i.faults, slot)
	return nil
}
func (i *fakePrivilegeInstance) Collect() error { return nil }

func (i *fakePrivilegeInstance) Ready() error { return i.readyErr }
func (i *fakePrivilegeInstance) SlotHealth(slot uint32) error {
	if i.faults[slot] > 0 {
		return errors.New("tracking fault")
	}
	return nil
}
func (i *fakePrivilegeInstance) Bind(b enforcement.Binding) error {
	i.bound[b.Container.CgroupID] = b.Slot
	return nil
}
func (i *fakePrivilegeInstance) Unbind(c enforcement.ContainerIdentity) error {
	delete(i.bound, c.CgroupID)
	return nil
}
func (i *fakePrivilegeInstance) Stop(context.Context) error { i.stops++; return i.stopErr }

type fakePrivilegeEngine struct {
	instances []*fakePrivilegeInstance
	configs   []privruntime.Config
	startErr  error
	failIf    func(privruntime.Config) bool
}

func (e *fakePrivilegeEngine) Start(_ context.Context, _ string, c privruntime.Config) (PrivilegeInstance, error) {
	if e.startErr != nil {
		return nil, e.startErr
	}
	if e.failIf != nil && e.failIf(c) {
		return nil, errors.New("does not fit")
	}
	i := &fakePrivilegeInstance{bound: map[uint64]uint32{}}
	for _, b := range c.InitialBindings {
		i.bound[b.Container.CgroupID] = b.Slot
	}
	e.instances = append(e.instances, i)
	e.configs = append(e.configs, c)
	return i, nil
}

func privBinding(cgroup uint64) sandboxpolicy.Binding {
	return sandboxpolicy.Binding{Runtime: "containerd", ContainerID: string(rune('a' + cgroup)), CgroupID: cgroup, CgroupPath: "/kubepods/c"}
}

func privPolicy(uid string, def api.Action, rules ...api.PrivilegeRule) sandboxpolicy.CompiledPolicy {
	return sandboxpolicy.CompiledPolicy{Identity: sandboxpolicy.PolicyIdentity{UID: types.UID(uid), Namespace: "ns", Name: uid}, Mode: api.ModeEnforce, Privilege: &api.PrivilegeSection{Default: def, Rules: rules}}
}

func privPlan(revision string, policies ...sandboxpolicy.CompiledPolicy) sandboxpolicy.Plan {
	return sandboxpolicy.Plan{Revision: revision, Policies: policies}
}

var denyMount = api.PrivilegeRule{Rule: api.Rule{Name: "no-mount", Action: api.ActionDeny, Origin: ptr("o")}, Target: api.PrivilegeTarget{Syscall: []string{"mount"}}}

func ptr(s string) *string { return &s }

var allowMount = api.PrivilegeRule{Rule: api.Rule{Name: "mount-ok", Action: api.ActionAllow}, Target: api.PrivilegeTarget{Syscall: []string{"mount"}}}

func TestPrivilegeNodeInstanceSharesSlots(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	plan := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	if r, err := b.Replace(ctx, privBinding(1), plan); err != nil || !r.Committed {
		t.Fatalf("first: %+v %v", r, err)
	}
	if r, err := b.Replace(ctx, privBinding(2), plan); err != nil || !r.Committed {
		t.Fatalf("second: %+v %v", r, err)
	}
	if len(e.instances) != 1 || e.instances[0].bound[2] != e.instances[0].bound[1] {
		t.Fatalf("same combination must share one slot in one instance: %d %+v", len(e.instances), e.instances[0].bound)
	}
	if s := b.Stats(); s.Replaced != 1 || s.Prepared != 1 {
		t.Fatalf("stats %+v", s)
	}
	// Same plan again: attestation, no new instance.
	if r, err := b.Replace(ctx, privBinding(1), plan); err != nil || !r.Committed || len(e.instances) != 1 {
		t.Fatalf("same plan: %+v %v", r, err)
	}
	if err := b.Attest(ctx, privBinding(1), "r1"); err != nil {
		t.Fatal(err)
	}
	// Withdraw is a live unbind.
	if r, err := b.Withdraw(ctx, privBinding(2)); err != nil || !r.Committed {
		t.Fatalf("withdraw: %+v %v", r, err)
	}
	if _, ok := e.instances[0].bound[2]; ok || len(e.instances) != 1 {
		t.Fatal("withdraw must unbind in the running instance")
	}
}

func TestPrivilegeNewCombinationPublishesInPlace(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Replace(ctx, privBinding(2), privPlan("r2", privPolicy("p2", api.ActionDeny))); err != nil {
		t.Fatal(err)
	}
	i := e.instances[0]
	if len(e.instances) != 1 || i.stops != 0 {
		t.Fatalf("a new combination must not start or stop an instance: %d instances", len(e.instances))
	}
	c, ok := i.published[i.bound[2]].(privpolicy.Compiled)
	if !ok || c.Slots != 1 || c.Generation <= e.configs[0].Policy.Generation || i.bound[2] == i.bound[1] {
		t.Fatalf("published: %+v bound=%v", i.published, i.bound)
	}
	// A failed publish keeps the instance, its slots and bindings.
	i.publishErr = errors.New("capacity")
	if r, err := b.Replace(ctx, privBinding(3), privPlan("r3", privPolicy("p3", api.ActionDeny))); err == nil || r.Committed {
		t.Fatalf("expected failure: %+v", r)
	}
	if i.stops != 0 || b.Attest(ctx, privBinding(1), "r1") != nil || b.Attest(ctx, privBinding(2), "r2") != nil {
		t.Fatal("the instance must keep running with its bindings")
	}
}

func TestPrivilegePrepareCreatesSlotBeforeContainer(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	plan := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{plan}); err != nil {
		t.Fatal(err)
	}
	if len(e.instances) != 1 || e.configs[0].Policy.Slots != 1 {
		t.Fatalf("prepare must create the slot: %d", len(e.instances))
	}
	if _, err := b.Replace(ctx, privBinding(1), plan); err != nil || len(e.instances) != 1 {
		t.Fatalf("bind after prepare must be live: %v instances=%d", err, len(e.instances))
	}
	if s := b.Stats(); s.Prepared != 1 || s.Replaced != 0 {
		t.Fatalf("stats %+v", s)
	}
	// The same prepare again changes nothing.
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{plan}); err != nil || len(e.instances) != 1 {
		t.Fatalf("repeat prepare: %v", err)
	}
}

func TestPrivilegeMergesPoliciesInOneSlot(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	plan := privPlan("r1", privPolicy("p1", api.ActionDeny, denyMount), privPolicy("p2", api.ActionAllow, allowMount))
	if _, err := b.Replace(context.Background(), privBinding(1), plan); err != nil {
		t.Fatal(err)
	}
	c := e.configs[0].Policy
	names := strings.Join(c.RuleNames, ",")
	if c.Slots != 1 || !strings.Contains(names, "ns/p1/no-mount") || !strings.Contains(names, "ns/p2/mount-ok") {
		t.Fatalf("merged slot: slots=%d names=%s", c.Slots, names)
	}
}

func TestPrivilegeRetriesFailedFree(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow))); err != nil {
		t.Fatal(err)
	}
	i := e.instances[0]
	old := i.bound[1]
	i.freeErr = errors.New("busy")
	r, err := b.Replace(ctx, privBinding(1), privPlan("r2", privPolicy("p1", api.ActionDeny)))
	if err == nil || !r.Committed || r.ActiveRevision != "r2" {
		t.Fatalf("committed with cleanup error expected: %+v %v", r, err)
	}
	i.freeErr = nil
	if _, err = b.Replace(ctx, privBinding(1), privPlan("r2", privPolicy("p1", api.ActionDeny))); err != nil || !i.freed[old] {
		t.Fatalf("retry: %v freed=%v", err, i.freed)
	}
}

// An instance that is not ready may still run its programs, so a withdraw
// there stays pending: it is retried, and a new instance never carries it.
func TestPrivilegeWithdrawPendingWhenInstanceNotReady(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow))); err != nil {
		t.Fatal(err)
	}
	e.instances[0].readyErr = errors.New("not ready")
	b.lastHeal = time.Now() // no recovery replacement in this part of the test
	if r, err := b.Withdraw(ctx, privBinding(1)); err == nil || r.Committed || !r.ProtectionUnconfirmed {
		t.Fatalf("withdraw on an instance that is not ready must stay pending: %+v %v", r, err)
	}
	// The retry on a ready instance unbinds and commits.
	e.instances[0].readyErr = nil
	if r, err := b.Withdraw(ctx, privBinding(1)); err != nil || !r.Committed {
		t.Fatalf("retry: %+v %v", r, err)
	}
	if _, bound := e.instances[0].bound[1]; bound {
		t.Fatal("the retry must unbind")
	}
	// Pending again, then a new instance replaces the old one: the withdrawn
	// container is not carried, and the next retry commits.
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow))); err != nil {
		t.Fatal(err)
	}
	e.instances[0].readyErr = errors.New("not ready")
	b.lastHeal = time.Now()
	if r, _ := b.Withdraw(ctx, privBinding(1)); r.Committed {
		t.Fatal("must stay pending")
	}
	if r, err := b.Replace(ctx, privBinding(2), privPlan("r2", privPolicy("p1", api.ActionAllow))); err != nil || !r.Committed {
		t.Fatalf("recovery: %+v %v", r, err)
	}
	if c := e.configs[len(e.configs)-1]; len(c.InitialBindings) > 1 {
		t.Fatalf("the withdrawn container must not be carried: %+v", c.InitialBindings)
	}
	if r, err := b.Withdraw(ctx, privBinding(1)); err != nil || !r.Committed {
		t.Fatalf("after the replacement: %+v %v", r, err)
	}
}

func TestPrivilegeOversizedPrepareDoesNotBlockContainers(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	var plans []sandboxpolicy.Plan
	for i := 0; i < 65; i++ { // one more than the slots per node
		plans = append(plans, privPlan("p", privPolicy(string(rune('A'+i)), api.ActionAllow)))
	}
	// The ones that fit are prepared; the others are logged, not an error.
	// 4 slots stay free for containers.
	if err := b.Prepare(ctx, plans); err != nil || len(e.instances) != 1 || e.configs[0].Policy.Slots != 64-prepareHeadroom || b.unfit != 5 {
		t.Fatalf("too many combinations: %v instances=%d unfit=%d", err, len(e.instances), b.unfit)
	}
	if r, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("real", api.ActionDeny))); err != nil || !r.Committed {
		t.Fatalf("a real container must still bind: %+v %v", r, err)
	}
}

func TestPrivilegeUnreadyCandidateThatFailsToStopIsRetried(t *testing.T) {
	e := &readyFailEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	if r, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow))); err == nil || r.Committed {
		t.Fatalf("an unready candidate must fail: %+v", r)
	}
	if len(b.retiring) != 1 {
		t.Fatal("a candidate that failed to stop must be kept for retry")
	}
	e.instance.stopErr = nil
	if err := b.Close(ctx); err != nil || e.instance.stops != 2 {
		t.Fatalf("close must retry the stop: %v stops=%d", err, e.instance.stops)
	}
}

type readyFailEngine struct{ instance *fakePrivilegeInstance }

func (e *readyFailEngine) Start(context.Context, string, privruntime.Config) (PrivilegeInstance, error) {
	e.instance = &fakePrivilegeInstance{readyErr: errors.New("not ready"), stopErr: errors.New("busy"), bound: map[uint64]uint32{}}
	return e.instance, nil
}

func TestPrivilegeTrackingFaultUnconfirmsAndHeals(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	plan := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	if _, err := b.Replace(ctx, privBinding(1), plan); err != nil {
		t.Fatal(err)
	}
	e.instances[0].faults = map[uint32]uint64{e.instances[0].bound[1]: 1}
	if b.Attest(ctx, privBinding(1), "r1") == nil {
		t.Fatal("a tracking fault must fail attestation")
	}
	// The same plan again heals in place: the instance arms the slot's
	// tasks again. No reload.
	i := e.instances[0]
	if r, err := b.Replace(ctx, privBinding(1), plan); err != nil || !r.Committed || len(e.instances) != 1 || i.heals != 1 {
		t.Fatalf("heal: %+v %v instances=%d heals=%d", r, err, len(e.instances), i.heals)
	}
	if err := b.Attest(ctx, privBinding(1), "r1"); err != nil {
		t.Fatalf("the healed slot has no fault: %v", err)
	}
	// A fault that recurs at once is not healed again before healRetry.
	i.faults = map[uint32]uint64{i.bound[1]: 1}
	if r, err := b.Replace(ctx, privBinding(1), plan); err == nil || r.Committed || !r.ProtectionUnconfirmed || i.heals != 1 {
		t.Fatalf("heal within healRetry: %+v %v heals=%d", r, err, i.heals)
	}
	b.lastHeal = b.lastHeal.Add(-healRetry)
	if r, err := b.Replace(ctx, privBinding(1), plan); err != nil || !r.Committed || len(e.instances) != 1 || i.heals != 2 {
		t.Fatalf("heal after healRetry: %+v %v instances=%d", r, err, len(e.instances))
	}
}

func testPodBinding(uid string, cgroup uint64, plan sandboxpolicy.Plan) sandboxpolicy.PodBinding {
	return sandboxpolicy.PodBinding{PodUID: types.UID(uid), Namespace: "ns", PodName: uid, CgroupID: cgroup, CgroupPath: "/kubepods/pod" + uid, Plan: plan}
}

func TestPrivilegePodBindings(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	p1 := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	p2 := privPlan("r2", privPolicy("p2", api.ActionDeny))
	// No slot yet: the pod waits for Prepare.
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p1)}); err != nil || len(e.instances) != 0 {
		t.Fatalf("no slot: %v instances %d", err, len(e.instances))
	}
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p1)}); err != nil {
		t.Fatal(err)
	}
	slot1, ok := e.instances[0].bound[100]
	if !ok {
		t.Fatal("the pod cgroup must be bound once its slot exists")
	}
	// A container of the pod binds to the same slot; the pod binding stays.
	if _, err := b.Replace(ctx, privBinding(1), p1); err != nil || e.instances[0].bound[1] != slot1 || len(e.instances) != 1 {
		t.Fatalf("container bind: %v %+v", err, e.instances[0].bound)
	}
	// A new combination is published in place; the pod binding stays.
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1, p2}); err != nil || len(e.instances) != 1 || e.instances[0].bound[100] != slot1 {
		t.Fatalf("prepare p2: %v", err)
	}
	// A changed plan moves the pod to the new slot in place.
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p2)}); err != nil || e.instances[0].bound[100] == e.instances[0].bound[1] {
		t.Fatalf("plan change: %v %+v", err, e.instances[0].bound)
	}
	// A recreated pod cgroup is a new identity: the old one is removed.
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 101, p2)}); err != nil {
		t.Fatal(err)
	}
	if _, old := e.instances[0].bound[100]; old {
		t.Fatal("the old pod cgroup must be unbound")
	}
	if _, ok := e.instances[0].bound[101]; !ok {
		t.Fatal("the new pod cgroup must be bound")
	}
	// A pod that is not given any more is unbound; containers stay.
	if err := b.BindPods(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[0].bound[101]; ok {
		t.Fatal("pod binding must be removed")
	}
	if _, ok := e.instances[0].bound[1]; !ok {
		t.Fatal("the container binding must stay")
	}
}

func TestPrivilegePodKeepsLastGoodUntilNewSlotIsReady(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	p1 := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p1)}); err != nil {
		t.Fatal(err)
	}
	old := e.instances[0].bound[100]
	// An edited policy without a slot yet: the last-good binding stays.
	edited := privPlan("r2", privPolicy("p1", api.ActionDeny))
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, edited)}); err != nil {
		t.Fatal(err)
	}
	if slot, ok := e.instances[0].bound[100]; !ok || slot != old {
		t.Fatal("an edit without a ready slot must keep the last-good pod binding")
	}
	// Incomplete input (an empty plan) keeps it too.
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, sandboxpolicy.Plan{})}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[0].bound[100]; !ok {
		t.Fatal("incomplete input must keep the pod binding")
	}
	// The new slot is ready: the pod moves to it.
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1, edited}); err != nil {
		t.Fatal(err)
	}
	last := e.instances[len(e.instances)-1]
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, edited)}); err != nil {
		t.Fatal(err)
	}
	if b.pods["a"] == nil || b.pods["a"].combination != func() string { c, _ := Combination(edited); return c }() {
		t.Fatal("the pod must move to the new slot once it is ready")
	}
	if _, ok := last.bound[100]; !ok {
		t.Fatal("the pod must be bound in the running instance")
	}
	// An authoritative removal unbinds it.
	if err := b.BindPods(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := last.bound[100]; ok {
		t.Fatal("a pod that is not given must be unbound")
	}
}

// A container that finds no free slot makes room by dropping the slots only
// Prepare wanted (they are freed after the quarantine), never the active pod
// bindings, and the running instance keeps protecting the pods. The retry
// binds.
func TestPrivilegeRetryNeverDropsPodBindings(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	podPlan := privPlan("r1", privPolicy("pod", api.ActionAllow, denyMount))
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{podPlan}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, podPlan)}); err != nil {
		t.Fatal(err)
	}
	i := e.instances[0]
	i.capacity = 2 // room for two slots only
	spare := privPlan("r2", privPolicy("spare", api.ActionDeny))
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{podPlan, spare}); err != nil {
		t.Fatal(err)
	}
	spareKey, _ := Combination(spare)
	spareSlot, ok := b.slots[spareKey]
	if !ok {
		t.Fatal("the spare combination must be prepared")
	}
	// No free slot: the prepared-only slot is freed, the container waits.
	if r, err := b.Replace(ctx, privBinding(1), privPlan("r3", privPolicy("new", api.ActionDeny))); err == nil || r.Committed {
		t.Fatalf("no free slot must be refused for now: %+v %v", r, err)
	}
	if !i.freed[spareSlot] || i.stops != 0 || b.pods["a"] == nil || i.bound[100] != b.slots[mustKey(t, podPlan)] {
		t.Fatalf("only the prepared slot is freed: freed=%v bound=%v", i.freed, i.bound)
	}
	// After the quarantine the retry binds.
	i.freed = nil
	if r, err := b.Replace(ctx, privBinding(1), privPlan("r3", privPolicy("new", api.ActionDeny))); err != nil || !r.Committed {
		t.Fatalf("the retry must bind: %+v %v", r, err)
	}
	if len(e.instances) != 1 {
		t.Fatal("no instance replacement")
	}
}

func mustKey(t *testing.T, plan sandboxpolicy.Plan) string {
	t.Helper()
	key, policies := Combination(plan)
	if len(policies) == 0 {
		t.Fatal("plan has no privilege policy")
	}
	return key
}

func TestPrivilegePrepareStartsInstanceWithoutPlans(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	// A privilege policy exists but no pod uses it yet: load the gadget now,
	// so the first container does not wait for the slow first load.
	if err := b.Prepare(ctx, nil); err != nil || len(e.instances) != 1 || e.configs[0].Policy.Slots != 0 {
		t.Fatalf("first prepare: %v instances=%d", err, len(e.instances))
	}
	if err := b.Prepare(ctx, nil); err != nil || len(e.instances) != 1 {
		t.Fatalf("a running instance must be kept: %v instances=%d", err, len(e.instances))
	}
	plan := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	if _, err := b.Replace(ctx, privBinding(1), plan); err != nil || len(e.instances) != 1 || len(e.instances[0].published) != 1 {
		t.Fatalf("first container: %v instances=%d", err, len(e.instances))
	}
}

func TestPrivilegeEmptyInstanceRetryWaits(t *testing.T) {
	e := &fakePrivilegeEngine{startErr: errors.New("load failed")}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	if err := b.Prepare(ctx, nil); err == nil {
		t.Fatal("the failed start must be reported")
	}
	e.startErr = nil
	if err := b.Prepare(ctx, nil); err != nil || len(e.instances) != 0 {
		t.Fatalf("an empty start must not be retried at once: %v instances=%d", err, len(e.instances))
	}
	// A real plan is not delayed.
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))}); err != nil || len(e.instances) != 1 {
		t.Fatalf("prepare with a plan: %v instances=%d", err, len(e.instances))
	}
}

func TestPrivilegeClearPreparedNeverStartsInstance(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	// No privilege policy is active and no instance runs: clearing must not
	// load the gadget, unlike Prepare with no plans.
	if err := b.ClearPrepared(ctx); err != nil || len(e.instances) != 0 {
		t.Fatalf("clear without instance: %v instances=%d", err, len(e.instances))
	}
	plan := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{plan}); err != nil || len(b.prepared) != 1 {
		t.Fatalf("prepare: %v prepared=%d", err, len(b.prepared))
	}
	if err := b.ClearPrepared(ctx); err != nil || len(b.prepared) != 0 || len(e.instances) != 1 {
		t.Fatalf("clear: %v prepared=%d instances=%d", err, len(b.prepared), len(e.instances))
	}
}

// Pod bindings live in the shared nodeOwner, so this covers the network and
// file sections too.
func TestNodeOwnerBoundPodPlansFollowBindings(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	gen := func(g int64) sandboxpolicy.Plan {
		p := privPolicy("p1", api.ActionAllow, denyMount)
		p.Identity.Generation = g
		return privPlan(fmt.Sprintf("r%d", g), p)
	}
	if plans, faulted := b.BoundPodPlans(); len(plans)+len(faulted) != 0 {
		t.Fatalf("no instance: %+v", plans)
	}
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{gen(1)}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, gen(1))}); err != nil {
		t.Fatal(err)
	}
	if plans, _ := b.BoundPodPlans(); len(plans) != 1 || plans[0].Policies[0].Identity.Generation != 1 {
		t.Fatalf("bound: %+v", plans)
	}
	// An edit with the same section content keeps the binding and reports the new generation.
	instances := len(e.instances)
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, gen(2))}); err != nil || len(e.instances) != instances {
		t.Fatalf("same content: %v instances %d", err, len(e.instances))
	}
	if plans, _ := b.BoundPodPlans(); len(plans) != 1 || plans[0].Policies[0].Identity.Generation != 2 {
		t.Fatalf("generation not refreshed: %+v", plans)
	}
	if err := b.BindPods(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if plans, faulted := b.BoundPodPlans(); len(plans)+len(faulted) != 0 {
		t.Fatalf("unbound pod still reported: %+v", plans)
	}
}

// A pod plan counts only where the witness counters prove it: the pod was
// bound in the current instance before its containers started, and its slot
// has no fault.
func TestPrivilegePodPlansNeedWitness(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	p1 := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	p2 := privPlan("r2", privPolicy("p2", api.ActionDeny))
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1}); err != nil {
		t.Fatal(err)
	}
	started := testPodBinding("s", 200, p1)
	started.ContainersStarted = true
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p1), started}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[0].bound[200]; ok {
		t.Fatal("a pod whose containers started must not get a pod binding")
	}
	if plans, faulted := b.BoundPodPlans(); len(plans) != 1 || len(faulted) != 0 {
		t.Fatalf("bound before start: %d confirmed, %d faulted", len(plans), len(faulted))
	}
	// A slot fault: the pod plan is faulted, not confirmed.
	e.instances[0].faults = map[uint32]uint64{e.instances[0].bound[100]: 1}
	if plans, faulted := b.BoundPodPlans(); len(plans) != 0 || len(faulted) != 1 {
		t.Fatalf("slot fault: %d confirmed, %d faulted", len(plans), len(faulted))
	}
	e.instances[0].faults = nil
	// The pod's containers start, then a new combination is published. The
	// instance stays, and so do the marks of the pod's running tasks: the
	// pod plan stays confirmed (no replacement unconfirms it any more).
	running := testPodBinding("a", 100, p1)
	running.ContainersStarted = true
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{running}); err != nil {
		t.Fatal(err)
	}
	if plans, _ := b.BoundPodPlans(); len(plans) != 1 {
		t.Fatal("a pod bound before its containers started stays confirmed in its instance")
	}
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1, p2}); err != nil || len(e.instances) != 1 {
		t.Fatalf("prepare p2: %v", err)
	}
	if _, ok := e.instances[0].bound[100]; !ok {
		t.Fatal("the pod binding must stay")
	}
	if plans, faulted := b.BoundPodPlans(); len(plans) != 1 || len(faulted) != 0 {
		t.Fatalf("after a publication: %d confirmed, %d faulted", len(plans), len(faulted))
	}
}

// PrepareReplace creates the slot and binds nothing; the Replace that follows
// is a live map write in the same instance.
func TestPrivilegePrepareReplaceMakesBindLive(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	p1 := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	if err := b.PrepareReplace(ctx, privBinding(1), p1); err != nil || len(e.instances) != 1 {
		t.Fatalf("prepare: %v instances %d", err, len(e.instances))
	}
	if _, bound := e.instances[0].bound[1]; bound {
		t.Fatal("prepare must not bind")
	}
	if r, err := b.Replace(ctx, privBinding(1), p1); err != nil || !r.Committed || len(e.instances) != 1 {
		t.Fatalf("replace: %+v %v instances %d", r, err, len(e.instances))
	}
	if b.Stats().Prepared != 1 || b.Stats().Replaced != 0 {
		t.Fatalf("the bind must be a live write: %+v", b.Stats())
	}
	// A prepared combination needs no new instance.
	if err := b.PrepareReplace(ctx, privBinding(2), p1); err != nil || len(e.instances) != 1 {
		t.Fatalf("second prepare: %v instances %d", err, len(e.instances))
	}
}

// While the instance is not ready, every pod plan is faulted.
func TestPrivilegePodPlansFaultedWhileNotReady(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	p1 := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p1)}); err != nil {
		t.Fatal(err)
	}
	e.instances[0].readyErr = errors.New("not ready")
	if plans, faulted := b.BoundPodPlans(); len(plans) != 0 || len(faulted) != 1 {
		t.Fatalf("not ready: %d confirmed, %d faulted", len(plans), len(faulted))
	}
}

// A bound pod whose containers started moves to its new slot when its plan
// changes, so a restarted container is never judged by a superseded plan; the
// move is not confirmed.
func TestPrivilegeStartedPodFollowsPlanChange(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	p1 := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	p2 := privPlan("r2", privPolicy("p1", api.ActionDeny))
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1, p2}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p1)}); err != nil {
		t.Fatal(err)
	}
	before := e.instances[0].bound[100]
	moved := testPodBinding("a", 100, p2)
	moved.ContainersStarted = true
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{moved}); err != nil {
		t.Fatal(err)
	}
	if e.instances[0].bound[100] == before {
		t.Fatal("the pod binding must move to the new plan's slot")
	}
	if plans, _ := b.BoundPodPlans(); len(plans) != 0 {
		t.Fatal("a move after the containers started is not confirmed")
	}
}

// A Prepare between PrepareReplace and Replace keeps the reserved slot, so the
// Replace stays a live map write.
func TestPrivilegeReservedSlotSurvivesPrepare(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	p1 := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	p2 := privPlan("r2", privPolicy("p2", api.ActionDeny))
	if err := b.PrepareReplace(ctx, privBinding(1), p1); err != nil {
		t.Fatal(err)
	}
	// The pod loop prepares another combination: a publication; the
	// reserved slot is not freed.
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p2}); err != nil || len(e.instances) != 1 || len(e.instances[0].freed) != 0 {
		t.Fatalf("prepare: %v instances %d", err, len(e.instances))
	}
	if r, err := b.Replace(ctx, privBinding(1), p1); err != nil || !r.Committed || len(e.instances) != 1 || b.Stats().Prepared != 1 {
		t.Fatalf("replace must be live: %+v %v instances %d", r, err, len(e.instances))
	}
}

// After healRetry, a withdraw on an instance that is not ready replaces it;
// the new instance never binds the withdrawn container.
func TestPrivilegePendingWithdrawReplacesInstance(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow))); err != nil {
		t.Fatal(err)
	}
	e.instances[0].readyErr = errors.New("not ready")
	if r, err := b.Withdraw(ctx, privBinding(1)); err != nil || !r.Committed || len(e.instances) != 2 {
		t.Fatalf("recovery: %+v %v instances %d", r, err, len(e.instances))
	}
	if _, bound := e.instances[1].bound[1]; bound {
		t.Fatal("the new instance must not bind the withdrawn container")
	}
}

// A PrepareReplace whose combination does not fit reserves nothing, so it
// never blocks another workload's replacement.
func TestPrivilegeFailedPrepareReservesNothing(t *testing.T) {
	big := privPlan("big", privPolicy("big", api.ActionDeny))
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	p1 := privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))
	if _, err := b.Replace(ctx, privBinding(1), p1); err != nil {
		t.Fatal(err)
	}
	e.instances[0].publishErr = errors.New("capacity")
	if err := b.PrepareReplace(ctx, privBinding(2), big); err == nil {
		t.Fatal("a combination that does not fit must fail")
	}
	if b.reserved != nil {
		t.Fatalf("nothing may be reserved: %v", b.reserved)
	}
}
