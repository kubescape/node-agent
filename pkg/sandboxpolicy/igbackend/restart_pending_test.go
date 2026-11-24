package igbackend

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

const markCgroup = 7

// pendingState is a previous run's state with one Strict pod mark on
// markCgroup that no bind took over, next to its slot 5.
func pendingState(i *fakePrivilegeInstance) {
	i.published = map[uint32]any{5: nil}
	i.adoptedCgroups = map[uint64]uint32{markCgroup: enforcement.PendingSlot}
	i.strictSlots = map[uint32]bool{5: true, enforcement.PendingSlot: true}
}

// markCondition is the state a drop path decides a previous run's pending
// mark in.
type markCondition struct {
	name                 string
	gate, synced, proven bool
	gone                 bool
	record               string // "", "held" (its bind failed), "committed" (Strict) or "committed-audit"
	dropOld              bool   // an old set's mark (another state) goes
	dropAdopted          bool   // an adopted mark (the restored state) goes
	withoutInstance      bool   // the row applies to the paths without an instance
}

// The ordering invariant, row by row: a previous run's (Strict) pending mark
// goes only when its cgroup is gone, when Synchronize proved the pod
// Unselected or absent, or when this run committed an entry of the cgroup of
// equal or stricter class (gate on: after Synchronize). Holding nothing is
// not a proof (an Unknown pod's mark stays). An adopted mark is the key of
// this run's binding of the cgroup: it stays while one exists (its bind takes
// the entry over).
var markConditions = []markCondition{
	{name: "gate off", withoutInstance: true},
	{name: "gate off, cgroup gone", gone: true, dropOld: true, dropAdopted: true, withoutInstance: true},
	{name: "gate on, before Synchronize", gate: true, withoutInstance: true},
	{name: "gate on, before Synchronize, cgroup gone", gate: true, gone: true, dropOld: true, dropAdopted: true, withoutInstance: true},
	{name: "gate on, after Synchronize, no binding, not proven (Unknown pod)", gate: true, synced: true, withoutInstance: true},
	{name: "gate on, after Synchronize, proven Unselected or absent", gate: true, synced: true, proven: true, dropOld: true, dropAdopted: true, withoutInstance: true},
	{name: "gate on, after Synchronize, a failed binding", gate: true, synced: true, record: "held"},
	{name: "gate on, after Synchronize, a committed Strict binding", gate: true, synced: true, record: "committed", dropOld: true},
	{name: "gate on, after Synchronize, a committed Audit binding", gate: true, synced: true, record: "committed-audit"},
	{name: "gate on, before Synchronize, a committed binding", gate: true, record: "committed"},
	{name: "gate off, a committed Strict binding", record: "committed", dropOld: true},
	{name: "gate off, a committed Audit binding", record: "committed-audit"},
	{name: "gate off, a failed binding", record: "held"},
}

// apply sets the condition on the owner (with a ready instance for a record).
func (c markCondition) apply(b *PrivilegeBackend) {
	b.gate = c.gate
	if c.synced {
		proven := map[uint64]bool{}
		if c.proven {
			proven[markCgroup] = true
		}
		b.SetNRISynced(1, proven)
	}
	if c.gone {
		b.cgroupGone = func(cgroup uint64) bool { return cgroup == markCgroup }
	}
	if c.record != "" {
		plan := strictPlan
		if c.record == "committed-audit" {
			plan = auditPlan
		}
		key, policies := Combination(plan)
		b.pods["r"] = &podBinding{pod: testPodBinding("r", markCgroup, plan), combination: key, policies: policies,
			pendingMark: true, strict: strictPolicies(policies), sequenced: true, bindPending: c.record == "held"}
	}
}

// fakePrivilegeInstance lists its adopted bindings (a Strict slot's class
// from strictSlots) and hands a binding over (NodeInstance.Rebind).
func (i *fakePrivilegeInstance) AdoptedEntries() map[uint64]enforcement.Entry {
	out := map[uint64]enforcement.Entry{}
	for cgroup, slot := range i.adoptedCgroups {
		out[cgroup] = enforcement.Entry{Slot: slot, Strict: i.strictSlots[slot]}
	}
	return out
}

func (i *fakePrivilegeInstance) Rebind(old enforcement.ContainerIdentity, next enforcement.Binding) error {
	if i.ids[old.Runtime+"/"+old.ID] != next.Container.CgroupID {
		return errors.New("rebind: the cgroup has no active binding of the old identity")
	}
	delete(i.ids, old.Runtime+"/"+old.ID)
	return i.Bind(next)
}

// Every drop path decides a previous run's pending mark by the ordering
// invariant, never by the slot's manifest policies or the cgroup's current
// plan (S1 review finding 7: policies[PendingSlot] is nil). Each path also
// has an Audit plan for the mark's cgroup, which on main drops an adopted
// Strict binding: a pending mark is not decided by it.
func TestPendingMarkDropPaths(t *testing.T) {
	ctx := context.Background()
	audit := []sandboxpolicy.CompiledPolicy{auditPolicy("a")}
	oldSet := func() map[string]map[uint64]enforcement.PinnedBinding {
		return map[string]map[uint64]enforcement.PinnedBinding{"/bpf/privilege/old": {
			4: {Slot: 5, Strict: true}, markCgroup: {Slot: enforcement.PendingSlot, Strict: true}}}
	}
	paths := []struct {
		name string
		// run sets the path up, applies c and runs the decision; it
		// returns whether the mark went.
		run             func(t *testing.T, c markCondition) bool
		adopted         bool
		withoutInstance bool
	}{
		{name: "converged Settle", adopted: true, run: func(t *testing.T, c markCondition) bool {
			b, e, _, _ := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, nil, pendingState)
			if err := b.Prepare(ctx, nil); err != nil {
				t.Fatal(err)
			}
			c.apply(b)
			b.desired = map[uint64][]sandboxpolicy.CompiledPolicy{markCgroup: audit}
			if err := b.Settle(ctx); err != nil {
				t.Fatal(err)
			}
			_, kept := e.instances[0].adoptedCgroups[markCgroup]
			if kept && b.pins.settled {
				t.Fatal("a kept mark keeps the section from settling")
			}
			return !kept
		}},
		{name: "deadline keep", adopted: true, run: func(t *testing.T, c markCondition) bool {
			b, e, _, _ := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, nil, pendingState)
			if err := b.Prepare(ctx, nil); err != nil {
				t.Fatal(err)
			}
			c.apply(b)
			b.desired = map[uint64][]sandboxpolicy.CompiledPolicy{markCgroup: audit}
			b.pins.snapshotSeen = true
			b.pins.start = time.Now().Add(-settleDeadline)
			if err := b.Prepare(ctx, nil); err != nil {
				t.Fatal(err)
			}
			_, kept := e.instances[0].adoptedCgroups[markCgroup]
			if kept && !b.pins.deadline {
				t.Fatal("a kept mark past the deadline is degraded")
			}
			return !kept
		}},
		{name: "pruneOldSet (not restored)", run: func(t *testing.T, c markCondition) bool {
			defer func(d time.Duration) { settleDeadline = d }(settleDeadline)
			settleDeadline = 0
			b, _, pins, _ := newPinnedBindings(t, map[string]error{"/bpf/privilege/old": nil}, oldSet(), errors.New("incompatible"), nil)
			if err := b.Prepare(ctx, nil); err != nil {
				t.Fatal(err)
			}
			c.apply(b)
			b.desired = map[uint64][]sandboxpolicy.CompiledPolicy{markCgroup: audit}
			b.pins.snapshotSeen = true
			if err := b.PoliciesListed(map[string]bool{}, nil); err != nil {
				t.Fatal(err)
			}
			_, kept := pins.bindings["/bpf/privilege/old"][markCgroup]
			if _, real := pins.bindings["/bpf/privilege/old"][4]; real {
				t.Fatal("the real-slot binding of a removed policy goes as on main")
			}
			return !kept
		}},
		{name: "converged Settle (old set)", run: func(t *testing.T, c markCondition) bool {
			b, _, pins, _ := newPinnedBindings(t, map[string]error{"/bpf/privilege/old": nil}, oldSet(), errors.New("incompatible"), nil)
			if err := b.Prepare(ctx, nil); err != nil {
				t.Fatal(err)
			}
			c.apply(b)
			if err := b.Settle(ctx); err != nil {
				t.Fatal(err)
			}
			_, kept := pins.bindings["/bpf/privilege/old"][markCgroup]
			kept = kept && pins.dirs["/bpf/privilege/old"]
			if kept && b.pins.settled {
				t.Fatal("a kept mark keeps the section from settling")
			}
			if _, real := pins.bindings["/bpf/privilege/old"][4]; kept && real {
				t.Fatal("the set keeps only its uncovered marks")
			}
			return !kept
		}},
		{name: "settleWithoutPlan", withoutInstance: true, run: func(t *testing.T, c markCondition) bool {
			b, _, pins, _ := newPinnedBindings(t, map[string]error{"/bpf/privilege/old": nil}, oldSet(), nil, pendingState)
			c.apply(b)
			if err := b.Settle(ctx); err != nil {
				t.Fatal(err)
			}
			return !pins.dirs["/bpf/privilege/old"]
		}},
		{name: "settleGoneWithoutInstance", withoutInstance: true, run: func(t *testing.T, c markCondition) bool {
			defer func(d time.Duration) { settleDeadline = d }(settleDeadline)
			settleDeadline = 0
			b, _, pins, _ := newPinnedBindings(t, map[string]error{"/bpf/privilege/old": nil}, oldSet(), nil, pendingState)
			c.apply(b)
			if err := b.PoliciesListed(map[string]bool{}, nil); err != nil {
				t.Fatal(err)
			}
			gone := !pins.dirs["/bpf/privilege/old"]
			if gone != b.pins.settled {
				t.Fatalf("the set goes with the settle: gone %v settled %v", gone, b.pins.settled)
			}
			return gone
		}},
	}
	for _, p := range paths {
		for _, c := range markConditions {
			if p.withoutInstance && !c.withoutInstance {
				continue // a record keeps these paths from running at all
			}
			t.Run(p.name+"/"+c.name, func(t *testing.T) {
				want := c.dropOld
				if p.adopted {
					want = c.dropAdopted
				}
				if got := p.run(t, c); got != want {
					t.Fatalf("the mark went: %v, want %v", got, want)
				}
			})
		}
	}
}

// With the gate on, settleWithoutPlan keeps an old set whose bindings cannot
// be read (it may hold a mark); with the gate off it goes as on main.
func TestSettleWithoutPlanUnreadableSet(t *testing.T) {
	for _, gate := range []bool{false, true} {
		b, _, pins, _ := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, nil, previousRun)
		b.gate = gate
		if err := b.Settle(context.Background()); err != nil {
			t.Fatal(err)
		}
		if pins.dirs["/bpf/privilege/old"] != gate {
			t.Fatalf("gate %v: the unreadable set kept %v", gate, pins.dirs["/bpf/privilege/old"])
		}
	}
}

// S1 review finding 7: restart reporting names a previous run's pending marks
// as pod marks, not as an unreadable slot whose manifest does not list its
// policies; on the restored path and from an old set alike.
func TestRestartReportsAdoptedPendingMarks(t *testing.T) {
	t.Run("restored", func(t *testing.T) {
		b, _, _, _ := newPinned(t, map[string]error{"/bpf/privilege/old": nil}, nil, func(i *fakePrivilegeInstance) {
			pendingState(i)
			i.adoptedCgroups[8] = enforcement.PendingSlot
		})
		if err := b.Prepare(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		var marks *sandboxpolicy.AdoptedSlot
		for _, a := range b.Adopted() {
			if a.Slot == enforcement.PendingSlot {
				marks = &a
			}
		}
		if marks == nil || !marks.PendingMark || marks.Unreadable || marks.LinkError != nil || marks.Bindings != 2 || len(marks.Policies) != 0 {
			t.Fatalf("adopted marks: %+v", marks)
		}
	})
	t.Run("old set", func(t *testing.T) {
		bindings := map[string]map[uint64]enforcement.PinnedBinding{"/bpf/privilege/old": {markCgroup: {Slot: enforcement.PendingSlot, Strict: true}}}
		b, _, _, _ := newPinnedBindings(t, map[string]error{"/bpf/privilege/old": nil}, bindings, errors.New("incompatible"), nil)
		got := b.Adopted()
		if len(got) != 1 || !got[0].PendingMark || got[0].Unreadable || got[0].LinkError != nil || got[0].Bindings != 1 {
			t.Fatalf("old set marks: %+v", got)
		}
	})
}

// Restart survival off: a mark would not outlive node-agent (Close keeps no
// pins), so none is written.
func TestMarkPodNeedsRestartSurvival(t *testing.T) {
	b, e := newGate(t)
	b.pins, b.survivalOff = nil, errors.New("boot id unreadable")
	if err := b.MarkPod(context.Background(), gatePod(strictPlan), seq(1, 1)); err == nil {
		t.Fatal("no mark without restart survival")
	}
	if len(e.last().entries) != 0 {
		t.Fatal("nothing written")
	}
}

// lockedInstance locks like enforcement.Bindings: one non-reentrant mutex
// around every method the owner can call (every NodeInstance method, the
// read-back and the adopted listing), held by DropAdopted while it calls
// keep. A keep that calls into the instance deadlocks, as it would on the
// real controller (S2 review v1, finding 1; v2, LOW 9). The enforcement
// package's TestDropAdoptedKeepMustNotReenter shows the same hazard on a
// real Bindings.
type lockedInstance struct {
	*gateInstance
	mu sync.Mutex
}

func (l *lockedInstance) lock() func() { l.mu.Lock(); return l.mu.Unlock }

func (l *lockedInstance) Ready() error { defer l.lock()(); return l.gateInstance.Ready() }
func (l *lockedInstance) SlotHealth(slot uint32) error {
	defer l.lock()()
	return l.gateInstance.SlotHealth(slot)
}
func (l *lockedInstance) Bind(b enforcement.Binding) error {
	defer l.lock()()
	return l.gateInstance.Bind(b)
}
func (l *lockedInstance) Unbind(c enforcement.ContainerIdentity) error {
	defer l.lock()()
	return l.gateInstance.Unbind(c)
}
func (l *lockedInstance) Rebind(old enforcement.ContainerIdentity, next enforcement.Binding) error {
	defer l.lock()()
	return l.gateInstance.Rebind(old, next)
}
func (l *lockedInstance) Stop(ctx context.Context) error {
	defer l.lock()()
	return l.gateInstance.Stop(ctx)
}
func (l *lockedInstance) Publish(slot uint32, compiled any) error {
	defer l.lock()()
	return l.gateInstance.Publish(slot, compiled)
}
func (l *lockedInstance) Free(slot uint32) error { defer l.lock()(); return l.gateInstance.Free(slot) }
func (l *lockedInstance) Available(slot uint32) bool {
	defer l.lock()()
	return l.gateInstance.Available(slot)
}
func (l *lockedInstance) Heal(slot uint32) error { defer l.lock()(); return l.gateInstance.Heal(slot) }
func (l *lockedInstance) Collect() error         { defer l.lock()(); return l.gateInstance.Collect() }
func (l *lockedInstance) PublishedSlots() map[uint32]uint64 {
	defer l.lock()()
	return l.gateInstance.PublishedSlots()
}
func (l *lockedInstance) AdoptedBindings() map[uint32]int {
	defer l.lock()()
	return l.gateInstance.AdoptedBindings()
}
func (l *lockedInstance) ResetFaults() error { defer l.lock()(); return l.gateInstance.ResetFaults() }
func (l *lockedInstance) AdoptedEntries() map[uint64]enforcement.Entry {
	defer l.lock()()
	return l.gateInstance.AdoptedEntries()
}
func (l *lockedInstance) ReadEntry(cgroup uint64) (enforcement.Entry, bool, error) {
	defer l.lock()()
	return l.gateInstance.ReadEntry(cgroup)
}
func (l *lockedInstance) EntryOf(b enforcement.Binding) enforcement.Entry {
	defer l.lock()()
	return l.gateInstance.EntryOf(b)
}
func (l *lockedInstance) DropAdopted(keep func(uint64, uint32, bool) bool) (int, error) {
	defer l.lock()()
	return l.gateInstance.DropAdopted(keep)
}

// Settling adopted pending marks never calls into the instance from
// DropAdopted's callback (S2 review v1, finding 1): the converged Settle and
// the deadline settle finish, both when the mark stays and when it goes. A
// deadlock fails the test at its timeout instead of hanging the suite.
func TestSettleAdoptedPendingMarksDoesNotDeadlock(t *testing.T) {
	for _, path := range []string{"converged Settle", "deadline", "in-place sweep"} {
		for _, gone := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, cgroup gone %v", path, gone), func(t *testing.T) {
				ctx := context.Background()
				e := &gateEngine{wrap: func(i *gateInstance) PrivilegeInstance { return &lockedInstance{gateInstance: i} }}
				b, err := NewPrivilege(e, nil, "n")
				if err != nil {
					t.Fatal(err)
				}
				if err := b.Prepare(ctx, nil); err != nil {
					t.Fatal(err)
				}
				i := e.last()
				i.entries[markCgroup] = enforcement.Binding{Container: enforcement.ContainerIdentity{Runtime: podRuntime, ID: "old", CgroupID: markCgroup}, Slot: enforcement.PendingSlot, Strict: true}
				i.adopted[markCgroup] = true
				b.pins = &pinning{restored: true, adopted: map[uint32]enforcement.PinnedSlot{}, sets: map[string]enforcement.PinManifest{},
					dirs: map[NodeInstance]string{}, restoredMaps: map[uint32]bool{}, start: time.Now()}
				if gone {
					b.SetCgroupGone(func(cgroup uint64) bool { return cgroup == markCgroup })
				}
				done := make(chan error, 1)
				go func() {
					if path == "in-place sweep" {
						// A heal: a new instance on the same state adopts
						// the mark, and its sweep drops what no bind took
						// over (sweepAdopted).
						b.mu.Lock()
						b.pins.adopted = map[uint32]enforcement.PinnedSlot{}
						b.started = true
						b.mu.Unlock()
						i.readyErr = errors.New("link detached")
						done <- b.Prepare(ctx, nil)
						return
					}
					if path == "deadline" {
						b.mu.Lock()
						b.pins.start = time.Now().Add(-settleDeadline)
						b.mu.Unlock()
						done <- b.Prepare(ctx, nil)
						return
					}
					done <- b.Settle(ctx)
				}()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("deadlock: the settle did not return")
				}
				last := e.last()
				if _, kept := last.entries[markCgroup]; kept == gone {
					t.Fatalf("the mark kept %v, cgroup gone %v", kept, gone)
				}
			})
		}
	}
}

// S2 review v2, finding 1 (the reviewer's repro): a restored run whose
// manifest lists no policy slot (pins.adopted empty) keeps a previous run's
// Strict pod mark (an Unknown pod). An in-place heal adopts it on the same
// state, and its sweep (sweepAdopted) must follow the mark rule, gate on or
// off, never DropAdopted(nil).
func TestInPlaceHealKeepsAdoptedMark(t *testing.T) {
	ctx := context.Background()
	for _, gate := range []bool{false, true} {
		t.Run(fmt.Sprintf("gate %v", gate), func(t *testing.T) {
			b, e := newGate(t)
			b.SetStartGate(gate)
			i := e.last()
			i.entries[markCgroup] = enforcement.Binding{Container: enforcement.ContainerIdentity{Runtime: podRuntime, ID: "old", CgroupID: markCgroup}, Slot: enforcement.PendingSlot, Strict: true}
			i.adopted[markCgroup] = true
			b.pins = &pinning{restored: true, adopted: map[uint32]enforcement.PinnedSlot{}, sets: map[string]enforcement.PinManifest{},
				dirs: map[NodeInstance]string{}, restoredMaps: map[uint32]bool{}, start: time.Now()}
			if b.adopting() {
				t.Fatal("the heal must not be an adopting start (the sweep's drop is armed)")
			}
			i.readyErr = errors.New("link detached")
			_ = b.Prepare(ctx, nil)
			n := e.last()
			if n == i {
				t.Fatal("no heal")
			}
			if _, ok := n.entries[markCgroup]; !ok {
				t.Fatal("the previous run's Strict mark was dropped by the heal's sweep")
			}
			// The kept mark is decided again at the converged Settle: with
			// its cgroup proven gone, it goes.
			b.SetCgroupGone(func(cgroup uint64) bool { return cgroup == markCgroup })
			if err := b.Settle(ctx); err != nil {
				t.Fatal(err)
			}
			if _, ok := n.entries[markCgroup]; ok {
				t.Fatal("a gone cgroup's mark goes at the converged Settle")
			}
		})
	}
}

// S2 review v2, LOW 5: a bound record whose plan's class is not known does
// not cover a previous run's Strict mark (unknown counts as Strict only to
// keep a binding, never to drop a mark).
func TestPendingCoveredNeedsAKnownClass(t *testing.T) {
	b, _ := newGate(t)
	b.pods["r"] = &podBinding{pod: testPodBinding("r", markCgroup, strictPlan), combination: "unknown"}
	if b.pendingCovered(markCgroup, true, true) {
		t.Fatal("an unknown class covers nothing")
	}
	key, policies := Combination(strictPlan)
	b.pods["r"].combination, b.combinations[key] = key, policies
	if !b.pendingCovered(markCgroup, true, true) {
		t.Fatal("a known Strict binding covers a Strict mark")
	}
}

// S2 review v3, finding 2 (the reviewer's repro b): a converged Settle on a
// state that was not restored removes the old sets, but never one that
// holds an uncovered pending mark (it keeps the set and does not settle).
func TestReviewV3ConvergedSettleOldSetMark(t *testing.T) {
	ctx := context.Background()
	for _, c := range markConditions {
		if c.record != "" {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			bindings := map[string]map[uint64]enforcement.PinnedBinding{"/bpf/privilege/old": {
				markCgroup: {Slot: enforcement.PendingSlot, Strict: true}}}
			b, _, pins, _ := newPinnedBindings(t, map[string]error{"/bpf/privilege/old": nil}, bindings, errors.New("incompatible"), nil)
			if err := b.Prepare(ctx, nil); err != nil {
				t.Fatal(err)
			}
			c.apply(b)
			if err := b.Settle(ctx); err != nil {
				t.Fatal(err)
			}
			_, kept := pins.bindings["/bpf/privilege/old"][markCgroup]
			gone := !pins.dirs["/bpf/privilege/old"] || !kept
			if gone != c.dropOld {
				t.Fatalf("mark went %v, want %v (settled %v)", gone, c.dropOld, b.pins.settled)
			}
		})
	}
}

// S2 review v3, finding 1 (the reviewer's repro a): a pod unmarked
// (Unselected) or released while the instance is not ready keeps its record
// through an in-place heal, so the next ready BindPods removes its Strict
// mark from the kernel (the candidate adopted it from the shared state).
func TestReviewV3PendingUnbindAcrossHeal(t *testing.T) {
	ctx := context.Background()
	for _, op := range []string{"unmark", "release"} {
		t.Run(op, func(t *testing.T) {
			b, e := newGate(t)
			b.SetStartGate(true)
			b.SetNRISynced(1, map[uint64]bool{})
			mustMark(t, b, strictPlan, seq(5, 5))
			i := e.last()
			i.readyErr = errors.New("link detached")
			var err error
			if op == "unmark" {
				err = b.UnmarkPod(ctx, "u", podCgroup, seq(6, 6))
			} else {
				err = b.ReleasePod(ctx, "u", podCgroup)
			}
			if err == nil || !b.pods["u"].pendingUnbind {
				t.Fatalf("pending: %v", err)
			}
			if op == "unmark" && b.removed[podCgroup] != seq(6, 6) {
				t.Fatalf("the pending unmark records its order at once: %v", b.removed)
			}
			_ = b.Prepare(ctx, nil) // heal in place
			n := e.last()
			if n == i {
				t.Fatal("no heal")
			}
			if p := b.pods["u"]; p == nil || !p.pendingUnbind {
				t.Fatalf("the removal is carried: %+v", p)
			}
			if c, f := b.BoundPodPlans(); len(c) != 0 || len(f) != 1 {
				t.Fatalf("status shows the pod faulted until its entry goes: confirmed %d faulted %d", len(c), len(f))
			}
			if op == "unmark" {
				if err := b.UnmarkPod(ctx, "u", podCgroup, seq(7, 7)); err != nil {
					t.Fatal(err)
				}
			}
			_ = b.Settle(ctx)
			_ = b.BindPods(ctx, nil)
			if _, ok := n.entries[podCgroup]; ok {
				t.Fatalf("%s: the Strict mark of a removed pod stays in the kernel (entry %+v)", op, n.entries[podCgroup])
			}
			if b.pods["u"] != nil {
				t.Fatal("the record goes with its entry")
			}
			if _, ok := b.removed[podCgroup]; ok != (op == "unmark") {
				t.Fatalf("an unmark keeps its order, a release does not: %v", b.removed)
			}
		})
	}
}

// S2 review v4, finding 1 (the reviewer's repro, plus an empty plan): a
// start gate pod bound to its slot is unmarked while the instance is not
// ready, the section heals in place, and a later BindPods(At) takes the
// removal back. The heal bound nothing for the carried record, and the
// sweep may drop its adopted entry: the record is a failed bind, so a
// take-back binds it again, and status never claims it confirmed without a
// kernel entry. The same holds on a restored state before Settle, where a
// converged Settle drops the adopted entry.
func TestReviewV4TakeBackAfterHeal(t *testing.T) {
	ctx := context.Background()
	for _, restored := range []bool{false, true} {
		for _, how := range []string{"BindPodsAt newer", "BindPods (main, no seq)", "BindPods with an empty plan"} {
			t.Run(fmt.Sprintf("restored %v, %s", restored, how), func(t *testing.T) {
				b, e := newGate(t)
				b.SetStartGate(true)
				b.SetNRISynced(1, map[uint64]bool{})
				mustMark(t, b, strictPlan, seq(5, 5))
				if err := b.EnsurePodBound(ctx, "u"); err != nil {
					t.Fatal(err)
				}
				if restored {
					// Before Settle: the heal is an adopting start (no drop
					// at its sweep); the converged Settle drops instead.
					b.pins.restored, b.pins.settled = true, false
					b.pins.adopted = map[uint32]enforcement.PinnedSlot{60: {Slot: 60}}
				}
				i := e.last()
				i.readyErr = errors.New("link detached")
				if err := b.UnmarkPod(ctx, "u", podCgroup, seq(6, 6)); err == nil {
					t.Fatal("pending expected")
				}
				_ = b.Prepare(ctx, nil) // heal in place
				n := e.last()
				if n == i {
					t.Fatal("no heal")
				}
				if restored {
					if !b.adopting() {
						t.Fatal("the heal must be an adopting start")
					}
					if err := b.Settle(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if p := b.pods["u"]; p == nil || !p.pendingUnbind || !p.bindPending {
					t.Fatalf("the carried bound record is a failed bind: %+v", p)
				}
				switch how {
				case "BindPodsAt newer":
					_ = b.BindPodsAt(ctx, []sandboxpolicy.PodBinding{gatePod(strictPlan)}, seq(7, 7))
				case "BindPods (main, no seq)":
					_ = b.BindPods(ctx, []sandboxpolicy.PodBinding{gatePod(strictPlan)})
				default:
					_ = b.BindPods(ctx, []sandboxpolicy.PodBinding{gatePod(sandboxpolicy.Plan{})})
				}
				p := b.pods["u"]
				entry, inKernel := n.entries[podCgroup]
				confirmed, _ := b.BoundPodPlans()
				c := b.ConfirmPod("u", podCgroup, strictPlan)
				if !inKernel && (len(confirmed) > 0 || c.State == sandboxpolicy.PodSectionConfirmed || (p != nil && !p.pendingUnbind && !p.bindPending)) {
					t.Fatalf("status claims protection without a kernel entry: record %+v confirmed %d ConfirmPod %v %q", p, len(confirmed), c.State, c.Reason)
				}
				if how != "BindPods with an empty plan" {
					key, _ := Combination(strictPlan)
					if !inKernel || entry.Slot != b.slots[key] || c.State != sandboxpolicy.PodSectionConfirmed {
						t.Fatalf("the take-back binds the pod again: entry %+v %v, ConfirmPod %v %q", entry, inKernel, c.State, c.Reason)
					}
				}
			})
		}
	}
}

// S2 review v4, LOW 3: a retry of an unmark that is still pending, at the
// same sequence, returns nil (not ErrStaleSequence).
func TestUnmarkPodRetryWhilePending(t *testing.T) {
	ctx := context.Background()
	b, e := newGate(t)
	mustMark(t, b, strictPlan, seq(5, 5))
	e.last().readyErr = errors.New("link detached")
	if err := b.UnmarkPod(ctx, "u", podCgroup, seq(6, 6)); err == nil {
		t.Fatal("pending expected")
	}
	if err := b.UnmarkPod(ctx, "u", podCgroup, seq(6, 6)); err != nil {
		t.Fatalf("a retry at the same sequence: %v", err)
	}
	if err := b.UnmarkPod(ctx, "u", podCgroup, seq(5, 6)); !errors.Is(err, sandboxpolicy.ErrStaleSequence) {
		t.Fatalf("an older one stays stale: %v", err)
	}
	// Once the instance is ready, the retry unbinds (S2 review v5, L1).
	e.last().readyErr = nil
	if err := b.UnmarkPod(ctx, "u", podCgroup, seq(6, 6)); err != nil {
		t.Fatalf("a ready retry: %v", err)
	}
	if _, ok := e.last().entries[podCgroup]; ok || b.pods["u"] != nil {
		t.Fatalf("the ready retry removes the record and its entry: %+v", b.pods["u"])
	}
}

// S2 review v5, L3: a take-back of a pending removal is decided with the
// plan change that comes with it. Main's BindPods (no sequence) listing the
// pod with an Audit plan is a refused loosening: the record stays pending
// unbind (not taken back as Strict), and the next ready call unbinds it.
func TestRefusedPlanChangeKeepsTheRemoval(t *testing.T) {
	ctx := context.Background()
	b, e := newGate(t)
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{strictPlan, auditPlan}); err != nil {
		t.Fatal(err)
	}
	mustMark(t, b, strictPlan, seq(5, 5))
	if err := b.EnsurePodBound(ctx, "u"); err != nil {
		t.Fatal(err)
	}
	i := e.last()
	i.readyErr = errors.New("link detached")
	if err := b.UnmarkPod(ctx, "u", podCgroup, seq(6, 6)); err == nil {
		t.Fatal("pending expected")
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{gatePod(auditPlan)}); err != nil {
		t.Fatal(err)
	}
	if p := b.pods["u"]; p == nil || !p.pendingUnbind || !p.strict {
		t.Fatalf("the refused loosening leaves the removal pending: %+v", p)
	}
	i.readyErr = nil
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{gatePod(auditPlan)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := i.entries[podCgroup]; ok || b.pods["u"] != nil {
		t.Fatalf("the next ready call unbinds it: record %+v entry %v", b.pods["u"], ok)
	}
}

// S2 review v4, LOW 4: a pod record waiting for its unbind gives no current
// class (it no longer decides the cgroup's adopted entries).
func TestCurrentStrictSkipsPendingUnbind(t *testing.T) {
	b, _ := newGate(t)
	mustMark(t, b, strictPlan, seq(5, 5))
	if _, ok := b.currentStrict(podCgroup); !ok {
		t.Fatal("a live record decides")
	}
	b.pods["u"].pendingUnbind = true
	if _, ok := b.currentStrict(podCgroup); ok {
		t.Fatal("a record waiting for its unbind does not")
	}
}

// S2 review v4, finding 1(b): a carried bound record waiting for its unbind
// (bindPending after the heal) may still hold an adopted entry (a restored
// state before Settle keeps it): every removal path unbinds it at once, so
// the Unselected or released pod is not judged by its old slot until Settle.
func TestCarriedBoundRecordRemovalUnbinds(t *testing.T) {
	ctx := context.Background()
	for _, op := range []string{"BindPods", "UnmarkPod", "ReleasePod"} {
		t.Run(op, func(t *testing.T) {
			b, e := newGate(t)
			mustMark(t, b, strictPlan, seq(5, 5))
			if err := b.EnsurePodBound(ctx, "u"); err != nil {
				t.Fatal(err)
			}
			b.pins.restored, b.pins.settled = true, false
			b.pins.adopted = map[uint32]enforcement.PinnedSlot{60: {Slot: 60}}
			e.last().readyErr = errors.New("link detached")
			if err := b.UnmarkPod(ctx, "u", podCgroup, seq(6, 6)); err == nil {
				t.Fatal("pending expected")
			}
			_ = b.Prepare(ctx, nil) // an adopting heal: no drop at its sweep
			n := e.last()
			if p := b.pods["u"]; p == nil || !p.bindPending || !n.adopted[podCgroup] {
				t.Fatalf("carried, its entry adopted: %+v adopted %v", p, n.adopted[podCgroup])
			}
			var err error
			switch op {
			case "BindPods":
				err = b.BindPods(ctx, nil)
			case "UnmarkPod":
				err = b.UnmarkPod(ctx, "u", podCgroup, seq(7, 7))
			default:
				err = b.ReleasePod(ctx, "u", podCgroup)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := n.entries[podCgroup]; ok || b.pods["u"] != nil {
				t.Fatalf("the removal unbinds the adopted entry: entry %v record %+v", ok, b.pods["u"])
			}
		})
	}
}
