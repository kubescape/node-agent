package igbackend

import (
	"context"
	"errors"
	"fmt"
	netpolicy "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_network/policy"
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
	// The instance starts empty; slot 0 is a publication.
	first := e.instances[0].published[e.instances[0].bound[1]].(netpolicy.Compiled).Generation
	got, ok := b.SlotPolicies(first, 0)
	if !ok || len(got) != 1 || got[0].Identity.Name != "p1" {
		t.Fatalf("first instance slot 0: %+v %v", got, ok)
	}
	// A caller cannot change the table.
	got[0].Revision = "changed"
	if again, _ := b.SlotPolicies(first, 0); again[0].Revision == "changed" {
		t.Fatal("SlotPolicies aliases the table")
	}
	// A new combination is published into the running instance: its own
	// generation, with its slot's policies.
	if _, err := b.Replace(ctx, privBinding(2), privPlan("r2", netPolicy("p2", "deny"))); err != nil {
		t.Fatal(err)
	}
	i := e.instances[0]
	slot := i.bound[2]
	published := i.published[slot].(netpolicy.Compiled).Generation
	if published <= first {
		t.Fatalf("publication generation %d", published)
	}
	if got, ok := b.SlotPolicies(published, slot); !ok || len(got) != 1 || got[0].Identity.Name != "p2" {
		t.Fatalf("published slot %d: %+v %v", slot, got, ok)
	}
	if _, ok := b.SlotPolicies(published, 0); ok {
		t.Fatal("a slot the publication does not hold")
	}
	if got, ok := b.SlotPolicies(first, 0); !ok || got[0].Identity.Name != "p1" {
		t.Fatal("the instance start keeps its table")
	}
	// Failed publications use generations but never remove a running table.
	i.publishErr = errors.New("capacity")
	for n := 0; n < 6; n++ {
		if _, err := b.Replace(ctx, privBinding(uint64(10+n)), privPlan("r", netPolicy(fmt.Sprintf("q%d", n), "deny"))); err == nil {
			t.Fatal("publish must fail")
		}
	}
	if n := len(b.tables); n != 2 {
		t.Fatalf("failed publications must not keep tables: %d tables", n)
	}
	// The last binding of the published slot leaves: the slot is freed
	// and its table dropped.
	if _, err := b.Withdraw(ctx, privBinding(2)); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.SlotPolicies(published, slot); ok || len(b.tables) != 1 {
		t.Fatalf("a freed slot keeps no table: %d tables", len(b.tables))
	}
	// The instance stops: it reports no more verdicts, and its
	// publications go with it.
	i.publishErr = nil
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if len(b.tables) != 0 {
		t.Fatalf("a stopped instance keeps no table: %d", len(b.tables))
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
	// An instance that is not ready is replaced (a policy change is not).
	old.readyErr = errors.New("not ready")
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

func TestInstanceTablesPerGeneration(t *testing.T) {
	i := &nativeNodeInstance{}
	// An instance start: slot i of the compile is binding slot i.
	i.remember(7, []string{"", "default", "ns/p/r"}, []string{"", "o"}, [][]string{nil, {"", "catalog/a"}}, 0)
	// A publication: its slot 0 is binding slot 5.
	i.remember(9, []string{"", "default", "ns/q/s"}, []string{""}, [][]string{{"catalog/b"}}, 5)
	v := func(generation uint64, reason string, slot uint32) sandboxpolicy.SectionVerdict {
		return sandboxpolicy.SectionVerdict{Generation: generation, Reason: reason, Slot: slot}
	}
	if got, ok := i.defaultOrigins(v(7, "section_default", 1)); !ok || !reflect.DeepEqual(got, []string{"", "catalog/a"}) {
		t.Fatalf("start slot 1: %#v %v", got, ok)
	}
	if got, ok := i.defaultOrigins(v(7, "section_default", 0)); !ok || got == nil || len(got) != 0 {
		t.Fatalf("a default with no origin must be [], not nil: %#v %v", got, ok)
	}
	if got, ok := i.defaultOrigins(v(9, "section_default", 5)); !ok || !reflect.DeepEqual(got, []string{"catalog/b"}) {
		t.Fatalf("publication at slot 5: %#v %v", got, ok)
	}
	if _, ok := i.defaultOrigins(v(9, "matching_rule", 5)); ok {
		t.Fatal("a rule verdict keeps its own origin")
	}
	if _, ok := i.defaultOrigins(v(9, "section_default", 0)); ok {
		t.Fatal("a slot the publication does not hold")
	}
	if names, _ := i.ids(9); len(names) != 3 || names[2] != "ns/q/s" {
		t.Fatalf("names of the publication: %v", names)
	}
	i.forgetTable(9)
	if names, origins := i.ids(9); names != nil || origins != nil {
		t.Fatal("a forgotten generation has no names")
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
	instance := e.instances[0].published[e.instances[0].bound[1]].(netpolicy.Compiled).Generation
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
