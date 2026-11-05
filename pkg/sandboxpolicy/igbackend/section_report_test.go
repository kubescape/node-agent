package igbackend

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
)

func TestSlotPoliciesFollowTheJudgingInstance(t *testing.T) {
	e := &fakeNetworkEngine{}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", netPolicy("p1", "allow", denyTestNet))); err != nil {
		t.Fatal(err)
	}
	first := e.configs[0].Policy.Generation
	if _, err := b.Replace(ctx, privBinding(2), privPlan("r2", netPolicy("p2", "deny"))); err != nil {
		t.Fatal(err)
	}
	second := e.configs[1].Policy.Generation
	if first == second {
		t.Fatal("each instance needs its own generation")
	}
	// The event's generation is the fence: a late event of the replaced
	// instance still gets that instance's slot, even if the slot numbers moved.
	got, ok := b.SlotPolicies(first, 0)
	if !ok || len(got) != 1 || got[0].Identity.Name != "p1" {
		t.Fatalf("first instance slot 0: %+v %v", got, ok)
	}
	for slot := uint32(0); slot < 2; slot++ {
		got, ok := b.SlotPolicies(second, slot)
		if !ok || len(got) != 1 {
			t.Fatalf("second instance slot %d: %+v %v", slot, got, ok)
		}
	}
	if _, ok := b.SlotPolicies(second, 2); ok {
		t.Fatal("a slot the instance does not have")
	}
	if _, ok := b.SlotPolicies(second+1, 0); ok {
		t.Fatal("an unknown generation")
	}
	// A caller cannot change the table.
	got, _ = b.SlotPolicies(first, 0)
	got[0].Revision = "changed"
	if again, _ := b.SlotPolicies(first, 0); again[0].Revision == "changed" {
		t.Fatal("SlotPolicies aliases the table")
	}
	// Old generations are forgotten: their events get no policy.
	for i := 3; i < 3+maxSlotTables; i++ {
		if _, err := b.Replace(ctx, privBinding(uint64(i)), privPlan("r", netPolicy("q"+string(rune('a'+i)), "deny"))); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := b.SlotPolicies(first, 0); ok {
		t.Fatal("an old generation must be forgotten")
	}
	if _, ok := b.SlotPolicies(e.configs[len(e.configs)-1].Policy.Generation, 0); !ok {
		t.Fatal("the current generation must be kept")
	}
}

type countingInstance struct {
	*fakePrivilegeInstance
	counters enforcement.VerdictCounters
	err      error
}

func (i *countingInstance) VerdictCounters() (enforcement.VerdictCounters, error) {
	return i.counters, i.err
}

type countingNetworkEngine struct {
	fakeNetworkEngine
	next []*countingInstance
}

func (e *countingNetworkEngine) Start(ctx context.Context, id string, c netruntime.Config) (NodeInstance, error) {
	i, err := e.fakeNetworkEngine.Start(ctx, id, c)
	if err != nil {
		return nil, err
	}
	n := e.next[0]
	e.next = e.next[1:]
	n.fakePrivilegeInstance = i.(*fakePrivilegeInstance)
	return n, nil
}

func TestVerdictStatsKeepRetiredInstances(t *testing.T) {
	old := &countingInstance{counters: enforcement.VerdictCounters{Denied: 10, Submitted: 7, Dropped: 1, RateLimited: 2}}
	current := &countingInstance{counters: enforcement.VerdictCounters{Denied: 3, Submitted: 3}}
	e := &countingNetworkEngine{next: []*countingInstance{old, current}}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", netPolicy("p1", "allow", denyTestNet))); err != nil {
		t.Fatal(err)
	}
	if s := b.VerdictStats(); s.Live != old.counters || s.Retired != (enforcement.VerdictCounters{}) || s.Unavailable != 0 {
		t.Fatalf("one instance: %+v", s)
	}
	if _, err := b.Replace(ctx, privBinding(2), privPlan("r2", netPolicy("p2", "deny"))); err != nil {
		t.Fatal(err)
	}
	// The replaced instance stopped: its last reading moves to Retired.
	s := b.VerdictStats()
	if old.stops != 1 || s.Retired != old.counters || s.Live != current.counters || s.Unavailable != 0 {
		t.Fatalf("after replacement: stops=%d %+v", old.stops, s)
	}
	current.err = errors.New("map gone")
	if s := b.VerdictStats(); s.Unavailable != 1 || s.Live != (enforcement.VerdictCounters{}) {
		t.Fatalf("an unreadable instance must be counted, not read as zero: %+v", s)
	}
}

func TestEnumName(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"FILE_ACCESS_READ", "FILE_ACCESS_"}:        "read",
		{"FILE_ACCESS_MOVE_SOURCE", "FILE_ACCESS_"}: "move_source",
		{"FILE_HOOK_FILE_OPEN", "FILE_HOOK_"}:       "file_open",
		{"PRIV_SC_UNSHARE", "PRIV_SC_"}:             "unshare",
		{"PRIV_SC_NONE", "PRIV_SC_"}:                "",
		{"NET_HOOK_SOCKET_CONNECT", "NET_HOOK_"}:    "socket_connect",
		{"", "NET_HOOK_"}:                           "",
	} {
		if got := enumName(in[0], in[1]); got != want {
			t.Errorf("enumName(%q) = %q, want %q", in[0], got, want)
		}
	}
}
