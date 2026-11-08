package igbackend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

type fakeNetworkEngine struct {
	instances []*fakePrivilegeInstance
	configs   []netruntime.Config
	startErr  error
}

func (e *fakeNetworkEngine) Start(_ context.Context, _ string, c netruntime.Config) (NodeInstance, error) {
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

func netPolicy(uid, def string, rules ...netpolicy.Rule) sandboxpolicy.CompiledPolicy {
	doc := netpolicy.Document{Version: 1, Policy: netpolicy.Policy{Mode: "enforce", Egress: netpolicy.Section{Default: def, Rules: rules}}}
	return sandboxpolicy.CompiledPolicy{Identity: sandboxpolicy.PolicyIdentity{UID: types.UID(uid), Namespace: "ns", Name: uid}, Mode: api.ModeEnforce, Network: &sandboxpolicy.NetworkPlan{Egress: doc}}
}

var denyTestNet = netpolicy.Rule{Name: "no-test-net", Action: "deny", CIDRs: []string{"192.0.2.0/24"}}

func TestNetworkNodeInstanceSlotsAndReplacement(t *testing.T) {
	e := &fakeNetworkEngine{}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	plan := privPlan("r1", netPolicy("p1", "allow", denyTestNet))
	for _, cgroup := range []uint64{1, 2} {
		if r, err := b.Replace(ctx, privBinding(cgroup), plan); err != nil || !r.Committed {
			t.Fatalf("bind %d: %+v %v", cgroup, r, err)
		}
	}
	if len(e.instances) != 1 || e.instances[0].bound[1] != e.instances[0].bound[2] {
		t.Fatal("same combination must share one slot in one instance")
	}
	if names := strings.Join(e.configs[0].Policy.RuleNames, ","); !strings.Contains(names, "ns/p1/no-test-net") {
		t.Fatalf("rule names %s", names)
	}
	// A changed policy (for example a class change) replaces the instance;
	// the new one starts with every container bound before the old one stops.
	changed := privPlan("r2", netPolicy("p1", "deny", denyTestNet))
	if _, err := b.Replace(ctx, privBinding(1), changed); err != nil {
		t.Fatal(err)
	}
	if len(e.instances) != 2 || e.instances[0].stops != 1 || len(e.configs[1].InitialBindings) != 2 || len(e.configs[1].Policy.Slots) != 2 {
		t.Fatalf("replacement: instances=%d stops=%d config=%+v", len(e.instances), e.instances[0].stops, e.configs[1])
	}
	if err := b.Attest(ctx, privBinding(2), "r1"); err != nil {
		t.Fatalf("the other container stays protected: %v", err)
	}
	// A failed candidate keeps the running instance.
	e.startErr = errors.New("load failed")
	if r, err := b.Replace(ctx, privBinding(3), privPlan("r3", netPolicy("p3", "deny"))); err == nil || r.Committed || e.instances[1].stops != 0 {
		t.Fatalf("failed candidate: %+v %v", r, err)
	}
	if r, err := b.Withdraw(ctx, privBinding(2)); err != nil || !r.Committed {
		t.Fatalf("withdraw %+v %v", r, err)
	}
	if _, ok := e.instances[1].bound[2]; ok {
		t.Fatal("withdraw must unbind in the running instance")
	}
}

func TestNetworkPrepareAndCombinationKey(t *testing.T) {
	e := &fakeNetworkEngine{}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	// As privilege, an instance with no slot starts without a network plan.
	if err := b.Prepare(ctx, nil); err != nil || len(e.instances) != 1 || len(e.configs[0].Policy.Slots) != 0 {
		t.Fatalf("empty prepare: %v instances=%d", err, len(e.instances))
	}
	p := netPolicy("p1", "allow", denyTestNet)
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{privPlan("r1", p)}); err != nil || len(e.instances) != 2 {
		t.Fatalf("prepare: %v", err)
	}
	// Only the gadget document is part of the key: a report change is a live bind.
	p.Network.Report.NotEnforced = []string{"rule serve: listen direction is not enforced"}
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r2", p)); err != nil || len(e.instances) != 2 || b.Stats().Prepared != 1 {
		t.Fatalf("bind after prepare must be live: %v instances=%d", err, len(e.instances))
	}
	// Privilege-only plans have no network combination.
	if key, policies := NetworkCombination(privPlan("x", privPolicy("p", api.ActionAllow))); key == "" || len(policies) != 0 {
		t.Fatal("privilege policies must not reach the network backend")
	}
}

// An active network policy loads the gadget before any pod matches it, so the
// first pod after a node-agent start finds an instance (startEmpty).
func TestNetworkEmptyInstance(t *testing.T) {
	e := &fakeNetworkEngine{}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	if err := b.Prepare(ctx, nil); err != nil || len(e.instances) != 1 || len(e.configs[0].Policy.Slots) != 0 || len(e.configs[0].InitialBindings) != 0 {
		t.Fatalf("first prepare: %v instances=%d", err, len(e.instances))
	}
	if err := b.Prepare(ctx, nil); err != nil || len(e.instances) != 1 {
		t.Fatalf("a running instance must be kept: %v instances=%d", err, len(e.instances))
	}
	// The first pod of the policy gets its slot by one replacement.
	plan := privPlan("r1", netPolicy("p1", "allow", denyTestNet))
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{plan}); err != nil || len(e.instances) != 2 || e.instances[0].stops != 1 {
		t.Fatalf("first pod: %v instances=%d", err, len(e.instances))
	}
}

func TestNetworkEmptyInstanceRetryWaits(t *testing.T) {
	e := &fakeNetworkEngine{startErr: errors.New("load failed")}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	if err := b.Prepare(ctx, nil); err == nil {
		t.Fatal("the failed start must be reported")
	}
	e.startErr = nil
	if err := b.Prepare(ctx, nil); err != nil || len(e.instances) != 0 {
		t.Fatalf("an empty start must not be retried at once: %v instances=%d", err, len(e.instances))
	}
	// After emptyRetry the empty start is tried again.
	b.emptyFailed = time.Now().Add(-emptyRetry)
	if err := b.Prepare(ctx, nil); err != nil || len(e.instances) != 1 {
		t.Fatalf("retry after the backoff: %v instances=%d", err, len(e.instances))
	}
	// A real plan is not delayed.
	e2 := &fakeNetworkEngine{startErr: errors.New("load failed")}
	b2, _ := NewNetwork(e2, nil, "n")
	_ = b2.Prepare(ctx, nil)
	e2.startErr = nil
	if err := b2.Prepare(ctx, []sandboxpolicy.Plan{privPlan("r1", netPolicy("p1", "allow", denyTestNet))}); err != nil || len(e2.instances) != 1 {
		t.Fatalf("prepare with a plan: %v instances=%d", err, len(e2.instances))
	}
}

func TestNetworkClearPreparedNeverStartsInstance(t *testing.T) {
	e := &fakeNetworkEngine{}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	// No network policy is active: clearing must not load the gadget.
	if err := b.ClearPrepared(ctx); err != nil || len(e.instances) != 0 {
		t.Fatalf("clear without instance: %v instances=%d", err, len(e.instances))
	}
}

func TestSelectNetworkTier(t *testing.T) {
	root := t.TempDir()
	lsm := filepath.Join(root, "sys/kernel/security/lsm")
	if err := os.MkdirAll(filepath.Dir(lsm), 0o755); err != nil {
		t.Fatal(err)
	}
	if tier, err := SelectNetworkTier(root, func() error { return nil }); err != nil || tier != NetworkTierCgroup {
		t.Fatalf("cgroup tier first: %q %v", tier, err)
	}
	var u *sandboxpolicy.EnforcementUnavailableError
	if _, err := SelectNetworkTier(root, nil); !errors.As(err, &u) || u.Section != "network" {
		t.Fatalf("no tier must be unavailable: %v", err)
	}
	if err := os.WriteFile(lsm, []byte("lockdown,capability,bpf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if tier, err := SelectNetworkTier(root, func() error { return errors.New("no sock_addr attach") }); err != nil || tier != NetworkTierLSM {
		t.Fatalf("LSM fallback: %q %v", tier, err)
	}
}

// The network section uses the generic pod-binding path of the node owner.
func TestNetworkPodBindings(t *testing.T) {
	e := &fakeNetworkEngine{}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	p1 := privPlan("r1", netPolicy("p1", "allow", denyTestNet))
	p2 := privPlan("r2", netPolicy("p2", "deny"))
	// No slot yet: the pod waits for Prepare.
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p1)}); err != nil || len(e.instances) != 0 {
		t.Fatalf("no slot: %v instances %d", err, len(e.instances))
	}
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1}); err != nil {
		t.Fatal(err)
	}
	// A pod plan with only privilege policies (the network policies of its
	// containers differ) has no network pod binding.
	privOnly := privPlan("rp", privPolicy("priv", api.ActionDeny))
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p1), testPodBinding("b", 200, privOnly)}); err != nil {
		t.Fatal(err)
	}
	slot1, ok := e.instances[0].bound[100]
	if _, other := e.instances[0].bound[200]; !ok || other {
		t.Fatalf("bound %+v", e.instances[0].bound)
	}
	// The first container of the pod binds to the same slot, live; the pod
	// binding stays.
	if _, err := b.Replace(ctx, privBinding(1), p1); err != nil || e.instances[0].bound[1] != slot1 || len(e.instances) != 1 || b.Stats().Prepared != 1 {
		t.Fatalf("container bind: %v %+v", err, e.instances[0].bound)
	}
	// A new combination replaces the instance (overlap); the pod binding is
	// carried. Network has no arming, so no SkipArming.
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{p1, p2}); err != nil || len(e.instances) != 2 || e.instances[0].stops != 1 {
		t.Fatalf("prepare p2: %v instances=%d", err, len(e.instances))
	}
	carried := false
	for _, initial := range e.configs[1].InitialBindings {
		if initial.Container.CgroupID == 100 {
			carried = !initial.SkipArming && initial.Container.Runtime == podRuntime && initial.Container.ID == "a"
		}
	}
	if !carried || e.instances[1].bound[100] != e.instances[1].bound[1] {
		t.Fatalf("pod binding not carried: %+v", e.configs[1].InitialBindings)
	}
	// The pod plan loses its network section: the pod is unbound; the
	// container binding stays.
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, privOnly)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[1].bound[100]; ok {
		t.Fatal("a pod plan without network policies must unbind the pod")
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, p2)}); err != nil || e.instances[1].bound[100] == e.instances[1].bound[1] {
		t.Fatalf("rebind to p2: %v %+v", err, e.instances[1].bound)
	}
	// A pod that is not given any more is unbound; the container stays.
	if err := b.BindPods(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.instances[1].bound[100]; ok {
		t.Fatal("pod binding must be removed")
	}
	if _, ok := e.instances[1].bound[1]; !ok {
		t.Fatal("the container binding must stay")
	}
}

// A cgroup tier that the gadget refuses below the cgroup-v2 root makes the
// network section unavailable (reason NetworkAttachNotRoot) until a start
// works; another start error does not.
func TestNetworkAttachNotRoot(t *testing.T) {
	refused := errors.Join(errors.New(`instantiating operator "enforce-network"`),
		&netruntime.CgroupRootError{Program: "ig_net_connect4", AttachTo: "/sys/fs/cgroup/kubepods.slice", CgroupID: 1234})
	err := networkStartError(refused)
	var u *sandboxpolicy.EnforcementUnavailableError
	if !errors.As(err, &u) || u.Reason != ReasonNetworkAttachNotRoot || u.Section != sandboxpolicy.SectionNetwork ||
		!strings.Contains(u.Detail, "kubepods.slice") || !strings.Contains(u.Detail, "cgroup ID 1") {
		t.Fatalf("mapped: %v", err)
	}
	other := errors.New("load failed")
	if networkStartError(other) != other {
		t.Fatal("another start error must stay as it is")
	}

	e := &fakeNetworkEngine{startErr: err}
	b, _ := NewNetwork(e, nil, "n")
	var _ sandboxpolicy.RuntimeAvailability = b
	ctx := context.Background()
	if err := b.Prepare(ctx, nil); err == nil {
		t.Fatal("the refused start must be reported")
	}
	if got := b.Unavailable(); !errors.As(got, &u) || u.Reason != ReasonNetworkAttachNotRoot {
		t.Fatalf("unavailable: %v", got)
	}
	e.startErr = other
	b.emptyFailed = time.Time{}
	if err := b.Prepare(ctx, nil); err == nil || b.Unavailable() == nil {
		t.Fatalf("another error keeps the reason: %v %v", err, b.Unavailable())
	}
	e.startErr = nil
	b.emptyFailed = time.Time{}
	if err := b.Prepare(ctx, nil); err != nil || b.Unavailable() != nil {
		t.Fatalf("a start that works clears the reason: %v %v", err, b.Unavailable())
	}
}
