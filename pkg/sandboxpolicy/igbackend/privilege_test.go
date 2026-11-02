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
}

func (i *fakePrivilegeInstance) Ready() error { return i.readyErr }
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
