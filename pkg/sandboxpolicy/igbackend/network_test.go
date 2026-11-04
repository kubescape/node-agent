package igbackend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	p := netPolicy("p1", "allow", denyTestNet)
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{privPlan("r1", p)}); err != nil || len(e.instances) != 1 {
		t.Fatalf("prepare: %v", err)
	}
	// Only the gadget document is part of the key: a report change is a live bind.
	p.Network.Report.NotEnforced = []string{"rule serve: listen direction is not enforced"}
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r2", p)); err != nil || len(e.instances) != 1 || b.Stats().Prepared != 1 {
		t.Fatalf("bind after prepare must be live: %v instances=%d", err, len(e.instances))
	}
	// Privilege-only plans have no network combination.
	if key, policies := NetworkCombination(privPlan("x", privPolicy("p", api.ActionAllow))); key == "" || len(policies) != 0 {
		t.Fatal("privilege policies must not reach the network backend")
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
