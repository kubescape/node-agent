package igbackend

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
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
}

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
}

func (e *fakePrivilegeEngine) Start(_ context.Context, _ string, c privruntime.Config) (PrivilegeInstance, error) {
	if e.startErr != nil {
		return nil, e.startErr
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

var denyMount = api.PrivilegeRule{Rule: api.Rule{Name: "no-mount", Action: api.ActionDeny, Origin: "o"}, Target: api.PrivilegeTarget{Syscall: []string{"mount"}}}
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

func TestPrivilegeNewCombinationReplacesWithOverlap(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow, denyMount))); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Replace(ctx, privBinding(2), privPlan("r2", privPolicy("p2", api.ActionDeny))); err != nil {
		t.Fatal(err)
	}
	if len(e.instances) != 2 || e.instances[0].stops != 1 || e.instances[1].stops != 0 {
		t.Fatal("the new instance starts before the old one stops")
	}
	if c := e.configs[1]; c.Policy.Slots != 2 || len(c.InitialBindings) != 2 || c.Policy.Generation <= e.configs[0].Policy.Generation {
		t.Fatalf("candidate must carry every slot and binding: %+v", c)
	}
	// A failed candidate keeps the old instance and state.
	e.startErr = errors.New("load failed")
	if r, err := b.Replace(ctx, privBinding(3), privPlan("r3", privPolicy("p3", api.ActionDeny))); err == nil || r.Committed {
		t.Fatalf("expected failure: %+v", r)
	}
	if e.instances[1].stops != 0 || b.Attest(ctx, privBinding(1), "r1") != nil {
		t.Fatal("old instance must keep running with its bindings")
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

func TestPrivilegeRetriesFailedStop(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow))); err != nil {
		t.Fatal(err)
	}
	e.instances[0].stopErr = errors.New("busy")
	r, err := b.Replace(ctx, privBinding(1), privPlan("r2", privPolicy("p1", api.ActionDeny)))
	if err == nil || !r.Committed || r.ActiveRevision != "r2" {
		t.Fatalf("committed with cleanup error expected: %+v %v", r, err)
	}
	e.instances[0].stopErr = nil
	if _, err = b.Replace(ctx, privBinding(1), privPlan("r2", privPolicy("p1", api.ActionDeny))); err != nil || e.instances[0].stops != 2 {
		t.Fatalf("retry: %v stops=%d", err, e.instances[0].stops)
	}
}

func TestPrivilegeWithdrawCommitsWhenInstanceDown(t *testing.T) {
	e := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(e, nil, "n")
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", privPolicy("p1", api.ActionAllow))); err != nil {
		t.Fatal(err)
	}
	e.instances[0].readyErr = errors.New("stopped")
	if r, err := b.Withdraw(ctx, privBinding(1)); err != nil || !r.Committed {
		t.Fatalf("withdraw on a stopped instance must commit: %+v %v", r, err)
	}
	// The next container recovers the node with a new instance.
	e.instances[0].readyErr = nil
	if r, err := b.Replace(ctx, privBinding(2), privPlan("r2", privPolicy("p1", api.ActionAllow))); err != nil || !r.Committed {
		t.Fatalf("recovery: %+v %v", r, err)
	}
	if c := e.configs[len(e.configs)-1]; len(c.InitialBindings) > 1 {
		t.Fatalf("the withdrawn container must not be carried: %+v", c.InitialBindings)
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
	if err := b.Prepare(ctx, plans); err == nil {
		t.Fatal("too many combinations must fail")
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
	// The same plan again replaces the instance, which arms the tasks again.
	if r, err := b.Replace(ctx, privBinding(1), plan); err != nil || !r.Committed || len(e.instances) != 2 {
		t.Fatalf("heal: %+v %v instances=%d", r, err, len(e.instances))
	}
	if err := b.Attest(ctx, privBinding(1), "r1"); err != nil {
		t.Fatalf("the new instance has no fault: %v", err)
	}
	// A fault that recurs at once does not reload the gadget again.
	e.instances[1].faults = map[uint32]uint64{e.instances[1].bound[1]: 1}
	if r, err := b.Replace(ctx, privBinding(1), plan); err == nil || r.Committed || !r.ProtectionUnconfirmed || len(e.instances) != 2 {
		t.Fatalf("heal within healRetry: %+v %v instances=%d", r, err, len(e.instances))
	}
	b.lastHeal = b.lastHeal.Add(-healRetry)
	if r, err := b.Replace(ctx, privBinding(1), plan); err != nil || !r.Committed || len(e.instances) != 3 {
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
	// A new combination replaces the instance; the pod binding is carried.
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1, p2}); err != nil || len(e.instances) != 2 {
		t.Fatalf("prepare p2: %v", err)
	}
	carried := false
	for _, initial := range e.configs[1].InitialBindings {
		if initial.Container.CgroupID == 100 {
			carried = initial.SkipArming && initial.Container.Runtime == podRuntime && initial.Container.ID == "a"
		}
	}
	if !carried {
		t.Fatalf("pod binding not carried without arming: %+v", e.configs[1].InitialBindings)
	}
	// A changed plan moves the pod to the new slot in place.
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p2)}); err != nil || e.instances[1].bound[100] == e.instances[1].bound[1] {
		t.Fatalf("plan change: %v %+v", err, e.instances[1].bound)
	}
	// A recreated pod cgroup is a new identity: the old one is removed.
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 101, p2)}); err != nil {
		t.Fatal(err)
	}
	if _, old := e.instances[1].bound[100]; old {
		t.Fatal("the old pod cgroup must be unbound")
	}
	if _, ok := e.instances[1].bound[101]; !ok {
		t.Fatal("the new pod cgroup must be bound")
	}
	// A pod that is not given any more is unbound; containers stay.
	if err := b.BindPods(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[1].bound[101]; ok {
		t.Fatal("pod binding must be removed")
	}
	if _, ok := e.instances[1].bound[1]; !ok {
		t.Fatal("the container binding must stay")
	}
}

func TestPrivilegePodUnboundWhenNewSlotIsMissing(t *testing.T) {
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
	// An edited policy without a slot yet: the old policy must not stay.
	edited := privPlan("r2", privPolicy("p1", api.ActionDeny))
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, edited)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[0].bound[100]; ok {
		t.Fatal("a pod whose new slot is missing must be unbound")
	}
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{edited}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, edited)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[len(e.instances)-1].bound[100]; !ok {
		t.Fatal("the pod must be bound once the new slot exists")
	}
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
	if _, err := b.Replace(ctx, privBinding(1), plan); err != nil || len(e.instances) != 2 {
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
