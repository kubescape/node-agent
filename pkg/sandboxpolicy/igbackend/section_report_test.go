package igbackend

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	filepolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_file/policy"
	netruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

func TestSlotPoliciesFollowTheJudgingInstance(t *testing.T) {
	e := &fakeNetworkEngine{}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	if _, err := b.Replace(ctx, privBinding(1), privPlan("r1", netPolicy("p1", "allow", denyTestNet))); err != nil {
		t.Fatal(err)
	}
	first := e.configs[0].Policy.Generation
	got, ok := b.SlotPolicies(first, 0)
	if !ok || len(got) != 1 || got[0].Identity.Name != "p1" {
		t.Fatalf("first instance slot 0: %+v %v", got, ok)
	}
	// A caller cannot change the table.
	got[0].Revision = "changed"
	if again, _ := b.SlotPolicies(first, 0); again[0].Revision == "changed" {
		t.Fatal("SlotPolicies aliases the table")
	}
	if _, err := b.Replace(ctx, privBinding(2), privPlan("r2", netPolicy("p2", "deny"))); err != nil {
		t.Fatal(err)
	}
	second := e.configs[1].Policy.Generation
	for slot := uint32(0); slot < 2; slot++ {
		if got, ok := b.SlotPolicies(second, slot); !ok || len(got) != 1 {
			t.Fatalf("second instance slot %d: %+v %v", slot, got, ok)
		}
	}
	if _, ok := b.SlotPolicies(second, 2); ok {
		t.Fatal("a slot the instance does not have")
	}
	// The replaced instance stopped: it reports no more verdicts.
	if e.instances[0].stops != 1 {
		t.Fatal("the first instance must be stopped")
	}
	if _, ok := b.SlotPolicies(first, 0); ok {
		t.Fatal("a stopped instance keeps no table")
	}
	// Failed starts use generations but never remove the running table.
	e.startErr = errors.New("load failed")
	for i := 0; i < 6; i++ {
		if _, err := b.Replace(ctx, privBinding(uint64(10+i)), privPlan("r", netPolicy(fmt.Sprintf("q%d", i), "deny"))); err == nil {
			t.Fatal("start must fail")
		}
	}
	if _, ok := b.SlotPolicies(second, 0); !ok {
		t.Fatal("failed starts removed the table of the running instance")
	}
	if n := len(b.tables); n != 1 {
		t.Fatalf("failed starts must not keep tables: %d tables", n)
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

func TestOriginOfUsesTheID(t *testing.T) {
	table := []string{"", "", "catalog/a"} // id 1 is an explicit empty origin
	if originOf(table, 0) != nil || originOf(table, 3) != nil {
		t.Fatal("id 0 and an id outside the table have no origin")
	}
	if o := originOf(table, 1); o == nil || *o != "" {
		t.Fatalf("explicit empty origin: %v", o)
	}
	if o := originOf(table, 2); o == nil || *o != "catalog/a" {
		t.Fatalf("origin: %v", o)
	}
}

func TestFileDefaultOriginsComeFromTheSlot(t *testing.T) {
	var slot1 [filepolicy.KernelAccessKinds][]string
	slot1[0] = []string{"", "catalog/a"} // read: an explicit "" and a label
	c := filepolicy.Compiled{DefaultOrigins: [][filepolicy.KernelAccessKinds][]string{{}, slot1}}
	verdict := func(reason string, slot uint32) sandboxpolicy.SectionVerdict {
		return sandboxpolicy.SectionVerdict{Reason: reason, Slot: slot}
	}
	if got, ok := defaultOrigins(c, verdict("section_default", 1), filepolicy.AccessRead); !ok || !reflect.DeepEqual(got, []string{"", "catalog/a"}) {
		t.Fatalf("read default of slot 1: %#v %v", got, ok)
	}
	if got, ok := defaultOrigins(c, verdict("section_default", 1), filepolicy.AccessWrite); !ok || got == nil || len(got) != 0 {
		t.Fatalf("a default with no origin must be [], not nil: %#v %v", got, ok)
	}
	if _, ok := defaultOrigins(c, verdict("matching_rule", 1), filepolicy.AccessRead); ok {
		t.Fatal("a rule verdict keeps its own origin")
	}
	if _, ok := defaultOrigins(c, verdict("section_default", 2), filepolicy.AccessRead); ok {
		t.Fatal("a slot outside the table")
	}
	if _, ok := defaultOrigins(c, verdict("section_default", 1), "move_source"); ok {
		t.Fatal("an event-only access kind has no default table")
	}
}

func TestSlotDefaultOrigins(t *testing.T) {
	table := [][]string{nil, {"", "catalog/a"}}
	if got, ok := slotDefaultOrigins(table, sandboxpolicy.SectionVerdict{Reason: "section_default", Slot: 1}); !ok || !reflect.DeepEqual(got, []string{"", "catalog/a"}) {
		t.Fatalf("slot 1: %#v %v", got, ok)
	}
	if got, ok := slotDefaultOrigins(table, sandboxpolicy.SectionVerdict{Reason: "section_default", Slot: 0}); !ok || got == nil || len(got) != 0 {
		t.Fatalf("a default with no origin must be [], not nil: %#v %v", got, ok)
	}
	if _, ok := slotDefaultOrigins(table, sandboxpolicy.SectionVerdict{Reason: "matching_rule", Slot: 1}); ok {
		t.Fatal("a rule verdict keeps its own origin")
	}
	if _, ok := slotDefaultOrigins(table, sandboxpolicy.SectionVerdict{Reason: "section_default", Slot: 2}); ok {
		t.Fatal("a slot outside the table")
	}
}

// An edit that leaves this section's content unchanged keeps the instance, but
// its verdicts must name the new generation, for containers and for pods.
func TestSlotPoliciesFollowGenerationWithoutReplacement(t *testing.T) {
	e := &fakeNetworkEngine{}
	b, _ := NewNetwork(e, nil, "n")
	ctx := context.Background()
	at := func(generation int64, revision string) sandboxpolicy.Plan {
		p := netPolicy("p1", "allow", denyTestNet)
		p.Identity.Generation = generation
		p.Revision = revision
		return privPlan(revision, p)
	}
	if _, err := b.Replace(ctx, privBinding(1), at(1, "r1")); err != nil {
		t.Fatal(err)
	}
	instance := e.configs[0].Policy.Generation
	if _, err := b.Replace(ctx, privBinding(1), at(2, "r2")); err != nil || len(e.configs) != 1 {
		t.Fatalf("same content must not replace the instance: %v configs=%d", err, len(e.configs))
	}
	if got, ok := b.SlotPolicies(instance, 0); !ok || got[0].Identity.Generation != 2 || got[0].Revision != "r2" {
		t.Fatalf("container edit: %+v %v", got, ok)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, at(2, "r2"))}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{testPodBinding("a", 100, at(3, "r3"))}); err != nil || len(e.configs) != 1 {
		t.Fatalf("pod edit: %v configs=%d", err, len(e.configs))
	}
	if got, _ := b.SlotPolicies(instance, 0); got[0].Identity.Generation != 3 {
		t.Fatalf("pod edit: %+v", got)
	}
}

// TestAsFault: a fault event of any section is an operational_error verdict
// with no rule and no match, and names its kind when the event has one.
func TestAsFault(t *testing.T) {
	for _, c := range []struct {
		kind uint32
		ok   bool
		want string
	}{{0, true, "structural"}, {1, true, "tracking"}, {7, true, ""}, {0, false, ""}} {
		v := sandboxpolicy.NewSectionVerdict(sandboxpolicy.SectionPrivilege, 3, 12, 2, 41, 0, true, "default", nil, "sh")
		v.Matches = []sandboxpolicy.RuleMatch{{Name: "x"}}
		if got := asFault(&v, c.kind, c.ok); got != c.want {
			t.Errorf("kind %d %v: %q, want %q", c.kind, c.ok, got, c.want)
		}
		if v.Reason != "operational_error" || v.Rule != sandboxpolicy.SectionRuleFault || v.Matches != nil || v.Verdict != "deny" {
			t.Errorf("fault verdict %+v", v)
		}
	}
}
