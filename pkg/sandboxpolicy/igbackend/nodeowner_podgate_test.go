package igbackend

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
	privruntime "github.com/kubescape/node-agent/pkg/ebpf/gadgets/enforce_privilege/runtime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
)

// gateInstance is a fake instance whose kernel binding map holds whole
// entries, as enforcement.Bindings does: one entry per cgroup, written by a
// bind, removed by an unbind of its identity (or of any identity when the
// entry is adopted: a previous instance on the same state wrote it), and read
// back. The class of a real slot is strictSlots'; a pending entry carries its
// own.
type gateInstance struct {
	*fakePrivilegeInstance
	entries map[uint64]enforcement.Binding
	adopted map[uint64]bool
	readErr error
	// unbindErr fails Unbind of a cgroup (S3: the ReleasePod retry).
	unbindErr map[uint64]error
	// binds counts the binds per cgroup; health counts SlotHealth calls.
	binds  map[uint64]int
	health int
}

func newGateInstance() *gateInstance {
	return &gateInstance{fakePrivilegeInstance: &fakePrivilegeInstance{bound: map[uint64]uint32{}, ids: map[string]uint64{}},
		entries: map[uint64]enforcement.Binding{}, adopted: map[uint64]bool{}, binds: map[uint64]int{}}
}

func (i *gateInstance) class(b enforcement.Binding) bool {
	if b.Slot == enforcement.PendingSlot {
		return b.Strict
	}
	return i.strictSlots[b.Slot]
}

func (i *gateInstance) Bind(b enforcement.Binding) error {
	cgroup := b.Container.CgroupID
	if err := i.bindErr[cgroup]; err != nil {
		return err
	}
	if e, ok := i.entries[cgroup]; ok && !i.adopted[cgroup] && e.Container != b.Container {
		return errors.New("cgroup identity conflicts with active binding")
	}
	i.entries[cgroup], i.binds[cgroup] = b, i.binds[cgroup]+1
	delete(i.adopted, cgroup)
	if b.Slot != enforcement.PendingSlot {
		i.bound[cgroup] = b.Slot // the slot is in use (Free refuses it)
	} else {
		delete(i.bound, cgroup)
	}
	return nil
}

func (i *gateInstance) Unbind(c enforcement.ContainerIdentity) error {
	if err := i.unbindErr[c.CgroupID]; err != nil {
		return err
	}
	if e, ok := i.entries[c.CgroupID]; ok && (i.adopted[c.CgroupID] || e.Container == c) {
		delete(i.entries, c.CgroupID)
		delete(i.adopted, c.CgroupID)
		delete(i.bound, c.CgroupID)
	}
	return nil
}

func (i *gateInstance) SlotHealth(slot uint32) error {
	i.health++
	return i.fakePrivilegeInstance.SlotHealth(slot)
}

func (i *gateInstance) ReadEntry(cgroup uint64) (enforcement.Entry, bool, error) {
	if i.readErr != nil {
		return enforcement.Entry{}, false, i.readErr
	}
	b, ok := i.entries[cgroup]
	if !ok {
		return enforcement.Entry{}, false, nil
	}
	return i.EntryOf(b), true, nil
}

func (i *gateInstance) EntryOf(b enforcement.Binding) enforcement.Entry {
	return enforcement.Entry{Slot: b.Slot, Subtree: b.Subtree, Strict: i.class(b), RuntimeHelpers: b.RuntimeHelpers}
}

func (i *gateInstance) AdoptedEntries() map[uint64]enforcement.Entry {
	out := map[uint64]enforcement.Entry{}
	for cgroup := range i.adopted {
		out[cgroup] = i.EntryOf(i.entries[cgroup])
	}
	return out
}

func (i *gateInstance) Rebind(old enforcement.ContainerIdentity, next enforcement.Binding) error {
	if e, ok := i.entries[next.Container.CgroupID]; !ok || e.Container != old {
		return errors.New("rebind: the cgroup has no active binding of the old identity")
	}
	delete(i.entries, next.Container.CgroupID)
	return i.Bind(next)
}

func (i *gateInstance) DropAdopted(keep func(uint64, uint32, bool) bool) (int, error) {
	n := 0
	for cgroup := range i.adopted {
		e := i.entries[cgroup]
		if keep != nil && keep(cgroup, e.Slot, i.class(e)) {
			n++
			continue
		}
		delete(i.entries, cgroup)
		delete(i.adopted, cgroup)
	}
	return n, nil
}

func (i *gateInstance) AdoptedBindings() map[uint32]int {
	out := map[uint32]int{}
	for cgroup := range i.adopted {
		out[i.entries[cgroup].Slot]++
	}
	return out
}

// gateEngine starts gateInstances. A new instance runs on the state of the
// last one (shared pinned maps): its published slots, and its entries as
// adopted ones.
type gateEngine struct {
	instances []*gateInstance
	configs   []privruntime.Config
	// onStart prepares each new instance before its initial binds; wrap
	// returns the instance the owner gets (nil: the gateInstance).
	onStart func(*gateInstance)
	wrap    func(*gateInstance) PrivilegeInstance
}

func (e *gateEngine) Start(_ context.Context, _ string, c privruntime.Config) (PrivilegeInstance, error) {
	i := newGateInstance()
	if n := len(e.instances); n > 0 {
		last := e.instances[n-1]
		i.published, i.strictSlots = map[uint32]any{}, last.strictSlots
		for slot, p := range last.published {
			i.published[slot] = p
		}
		for cgroup, b := range last.entries {
			i.entries[cgroup], i.adopted[cgroup] = b, true
		}
	}
	if e.onStart != nil {
		e.onStart(i)
	}
	for _, b := range c.InitialBindings {
		_ = i.Bind(b)
	}
	e.instances = append(e.instances, i)
	e.configs = append(e.configs, c)
	if e.wrap != nil {
		return e.wrap(i), nil
	}
	return i, nil
}

func (e *gateEngine) last() *gateInstance { return e.instances[len(e.instances)-1] }

// newGate starts a privilege owner with a ready, empty instance.
func newGate(t *testing.T) (*PrivilegeBackend, *gateEngine) {
	t.Helper()
	e := &gateEngine{}
	b, err := NewPrivilege(e, nil, "n")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Prepare(context.Background(), nil); err != nil || len(e.instances) != 1 {
		t.Fatalf("start: %v instances=%d", err, len(e.instances))
	}
	survive(b)
	return b, e
}

// survive turns restart survival on (a mark must outlive node-agent), with
// nothing left to settle from a previous run.
func survive(b *PrivilegeBackend) {
	b.pins = &pinning{settled: true, adopted: map[uint32]enforcement.PinnedSlot{}, sets: map[string]enforcement.PinManifest{},
		dirs: map[NodeInstance]string{}, restoredMaps: map[uint32]bool{}, start: time.Now()}
}

func seq(config, epoch uint64) sandboxpolicy.Seq {
	return sandboxpolicy.Seq{Config: config, Input: epoch}
}

var (
	strictPlan  = privPlan("", privPolicy("strict", api.ActionDeny, denyMount))
	strictPlan2 = privPlan("", privPolicy("strict2", api.ActionDeny))
	auditPlan   = privPlan("", auditPolicy("audit"))
)

func auditPolicy(uid string) sandboxpolicy.CompiledPolicy {
	p := privPolicy(uid, api.ActionDeny)
	p.Mode = api.ModeAudit
	return p
}

const podCgroup = 100

func gatePod(plan sandboxpolicy.Plan) sandboxpolicy.PodBinding {
	return testPodBinding("u", podCgroup, plan)
}

// mustMark marks the pod and fails the test on an error.
func mustMark(t *testing.T, b *PrivilegeBackend, plan sandboxpolicy.Plan, s sandboxpolicy.Seq) {
	t.Helper()
	if err := b.MarkPod(context.Background(), gatePod(plan), s); err != nil {
		t.Fatalf("mark: %v", err)
	}
}

// MarkPod's transitions: absent to pending and Audit to Strict at a newer or
// equal sequence, Strict to Audit only at a newer one, a plan change of a
// pending mark at a newer or equal one. A refused write is ErrStaleSequence
// and changes nothing; a write that changes nothing needs no order.
func TestMarkPodTransitions(t *testing.T) {
	tests := []struct {
		name string
		// setup runs on the owner before the call.
		setup func(t *testing.T, b *PrivilegeBackend)
		plan  sandboxpolicy.Plan
		seq   sandboxpolicy.Seq
		stale bool
		// want is the record's class and plan and lastSeq after the call.
		wantStrict bool
		wantPlan   sandboxpolicy.Plan
		wantSeq    sandboxpolicy.Seq
		// writes is the number of kernel writes of the call.
		writes int
	}{
		{name: "absent to Audit pending", plan: auditPlan, seq: seq(1, 1), wantPlan: auditPlan, wantSeq: seq(1, 1), writes: 1},
		{name: "absent to Strict pending", plan: strictPlan, seq: seq(1, 1), wantStrict: true, wantPlan: strictPlan, wantSeq: seq(1, 1), writes: 1},
		{name: "Audit to Strict, equal", setup: markAt(auditPlan, seq(5, 5)), plan: strictPlan, seq: seq(5, 5), wantStrict: true, wantPlan: strictPlan, wantSeq: seq(5, 5), writes: 1},
		{name: "Audit to Strict, newer", setup: markAt(auditPlan, seq(5, 5)), plan: strictPlan, seq: seq(6, 5), wantStrict: true, wantPlan: strictPlan, wantSeq: seq(6, 5), writes: 1},
		{name: "Audit to Strict, older", setup: markAt(auditPlan, seq(5, 5)), plan: strictPlan, seq: seq(4, 5), stale: true, wantPlan: auditPlan, wantSeq: seq(5, 5)},
		{name: "Audit to Strict, incomparable", setup: markAt(auditPlan, seq(5, 5)), plan: strictPlan, seq: seq(6, 4), stale: true, wantPlan: auditPlan, wantSeq: seq(5, 5)},
		{name: "Strict to Audit, newer", setup: markAt(strictPlan, seq(5, 5)), plan: auditPlan, seq: seq(5, 6), wantPlan: auditPlan, wantSeq: seq(5, 6), writes: 1},
		{name: "Strict to Audit, equal", setup: markAt(strictPlan, seq(5, 5)), plan: auditPlan, seq: seq(5, 5), stale: true, wantStrict: true, wantPlan: strictPlan, wantSeq: seq(5, 5)},
		{name: "Strict to Audit, older", setup: markAt(strictPlan, seq(5, 5)), plan: auditPlan, seq: seq(4, 4), stale: true, wantStrict: true, wantPlan: strictPlan, wantSeq: seq(5, 5)},
		{name: "Strict to Audit, incomparable", setup: markAt(strictPlan, seq(5, 5)), plan: auditPlan, seq: seq(4, 6), stale: true, wantStrict: true, wantPlan: strictPlan, wantSeq: seq(5, 5)},
		{name: "plan change, same class, equal", setup: markAt(strictPlan, seq(5, 5)), plan: strictPlan2, seq: seq(5, 5), wantStrict: true, wantPlan: strictPlan2, wantSeq: seq(5, 5)},
		{name: "plan change, same class, older", setup: markAt(strictPlan, seq(5, 5)), plan: strictPlan2, seq: seq(5, 4), stale: true, wantStrict: true, wantPlan: strictPlan, wantSeq: seq(5, 5)},
		{name: "same mark, older: nothing to write", setup: markAt(strictPlan, seq(5, 5)), plan: strictPlan, seq: seq(4, 4), wantStrict: true, wantPlan: strictPlan, wantSeq: seq(5, 5)},
		{name: "same mark, newer: order moves on", setup: markAt(strictPlan, seq(5, 5)), plan: strictPlan, seq: seq(7, 7), wantStrict: true, wantPlan: strictPlan, wantSeq: seq(7, 7)},
		{name: "after a removal, equal", setup: removedAt(seq(5, 5)), plan: strictPlan, seq: seq(5, 5), wantStrict: true, wantPlan: strictPlan, wantSeq: seq(5, 5), writes: 1},
		{name: "after a removal, older", setup: removedAt(seq(5, 5)), plan: strictPlan, seq: seq(4, 5), stale: true},
		{name: "after a removal, incomparable", setup: removedAt(seq(5, 5)), plan: strictPlan, seq: seq(6, 4), stale: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, e := newGate(t)
			if tt.setup != nil {
				tt.setup(t, b)
			}
			i := e.last()
			before := i.binds[podCgroup]
			err := b.MarkPod(context.Background(), gatePod(tt.plan), tt.seq)
			if tt.stale != errors.Is(err, sandboxpolicy.ErrStaleSequence) || (!tt.stale && err != nil) {
				t.Fatalf("MarkPod: %v, stale %v", err, tt.stale)
			}
			if got := i.binds[podCgroup] - before; got != tt.writes {
				t.Fatalf("%d kernel writes, want %d", got, tt.writes)
			}
			p := b.pods["u"]
			if tt.wantPlan.Policies == nil {
				if p != nil {
					t.Fatalf("a refused mark leaves no record: %+v", p)
				}
				if _, ok := i.entries[podCgroup]; ok {
					t.Fatal("a refused mark writes no entry")
				}
				return
			}
			key, _ := Combination(tt.wantPlan)
			if p == nil || !p.pendingMark || !p.sequenced || p.strict != tt.wantStrict || p.combination != key || p.lastSeq != tt.wantSeq {
				t.Fatalf("record %+v, want Strict %v, lastSeq %v", p, tt.wantStrict, tt.wantSeq)
			}
			entry := i.entries[podCgroup]
			if entry.Slot != enforcement.PendingSlot || entry.Strict != tt.wantStrict || !entry.Subtree || entry.Container.Runtime != podRuntime {
				t.Fatalf("kernel entry %+v, want a pending pod mark, Strict %v", entry, tt.wantStrict)
			}
		})
	}
}

func markAt(plan sandboxpolicy.Plan, s sandboxpolicy.Seq) func(*testing.T, *PrivilegeBackend) {
	return func(t *testing.T, b *PrivilegeBackend) { mustMark(t, b, plan, s) }
}

// removedAt marks the pod, then removes it with an authoritative removal at s.
func removedAt(s sandboxpolicy.Seq) func(*testing.T, *PrivilegeBackend) {
	return func(t *testing.T, b *PrivilegeBackend) {
		mustMark(t, b, strictPlan, seq(1, 1))
		if err := b.UnmarkPod(context.Background(), "u", podCgroup, s); err != nil {
			t.Fatal(err)
		}
		if b.pods["u"] != nil {
			t.Fatal("the removal must apply")
		}
	}
}

// MarkPod never writes a pending mark over an entry on a policy slot: an
// adopted one a previous run left, or one this run bound. A pod bound to the
// plan already needs no mark; one bound to another plan is refused. A
// previous run's pending mark is taken over.
func TestMarkPodNeverOverwritesARealSlotEntry(t *testing.T) {
	ctx := context.Background()
	// An adopted policy entry is ErrPolicyEntry only when it is as strict
	// as the plan; a looser one is another error (not covered).
	for _, tt := range []struct {
		name            string
		entryStrict     bool
		plan            sandboxpolicy.Plan
		wantPolicyEntry bool
	}{
		{name: "adopted Strict slot, Strict plan", entryStrict: true, plan: strictPlan, wantPolicyEntry: true},
		{name: "adopted Strict slot, Audit plan", entryStrict: true, plan: auditPlan, wantPolicyEntry: true},
		{name: "adopted Audit slot, Audit plan", plan: auditPlan, wantPolicyEntry: true},
		{name: "adopted Audit slot, Strict plan", plan: strictPlan},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, e := newGate(t)
			i := e.last()
			i.strictSlots = map[uint32]bool{5: tt.entryStrict}
			previous := enforcement.Binding{Container: enforcement.ContainerIdentity{Runtime: podRuntime, ID: "u", CgroupID: podCgroup}, Slot: 5, Subtree: true}
			i.entries[podCgroup], i.adopted[podCgroup] = previous, true
			err := b.MarkPod(ctx, gatePod(tt.plan), seq(1, 1))
			if err == nil || errors.Is(err, sandboxpolicy.ErrPolicyEntry) != tt.wantPolicyEntry {
				t.Fatalf("MarkPod: %v, want ErrPolicyEntry %v", err, tt.wantPolicyEntry)
			}
			if i.entries[podCgroup] != previous || !i.adopted[podCgroup] || b.pods["u"] != nil {
				t.Fatalf("never written over: entry %+v", i.entries[podCgroup])
			}
		})
	}
	t.Run("bound by this run", func(t *testing.T) {
		b, e := newGate(t)
		if err := b.Prepare(ctx, []sandboxpolicy.Plan{strictPlan}); err != nil {
			t.Fatal(err)
		}
		if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{gatePod(strictPlan)}); err != nil {
			t.Fatal(err)
		}
		i := e.last()
		bound := i.entries[podCgroup]
		if bound.Slot == enforcement.PendingSlot || b.pods["u"] == nil {
			t.Fatalf("not bound: %+v", bound)
		}
		if err := b.MarkPod(ctx, gatePod(strictPlan), seq(3, 3)); err != nil || i.entries[podCgroup] != bound {
			t.Fatalf("the same plan: %v, entry %+v", err, i.entries[podCgroup])
		}
		if p := b.pods["u"]; p.sequenced || p.pendingMark {
			t.Fatalf("a record main bound stays unordered (no sequence to seed it from): %+v", p)
		}
		if err := b.MarkPod(ctx, gatePod(auditPlan), seq(4, 4)); err == nil || errors.Is(err, sandboxpolicy.ErrPolicyEntry) || i.entries[podCgroup] != bound {
			t.Fatalf("another plan is not covered: %v, entry %+v", err, i.entries[podCgroup])
		}
		b.pods["u"].bindPending = true // a failed bind: nothing protects it
		if err := b.MarkPod(ctx, gatePod(strictPlan), seq(5, 5)); err == nil || errors.Is(err, sandboxpolicy.ErrPolicyEntry) {
			t.Fatalf("a failed bind is not covered: %v", err)
		}
	})
	t.Run("adopted pending mark", func(t *testing.T) {
		b, e := newGate(t)
		i := e.last()
		i.entries[podCgroup] = enforcement.Binding{Container: enforcement.ContainerIdentity{Runtime: podRuntime, ID: "u", CgroupID: podCgroup}, Slot: enforcement.PendingSlot, Strict: true, Subtree: true}
		i.adopted[podCgroup] = true
		if err := b.MarkPod(ctx, gatePod(auditPlan), seq(1, 1)); err != nil {
			t.Fatal(err)
		}
		if entry := i.entries[podCgroup]; entry.Strict || i.adopted[podCgroup] || entry.Slot != enforcement.PendingSlot {
			t.Fatalf("this run's mark takes the previous run's over: %+v adopted %v", entry, i.adopted[podCgroup])
		}
	})
}

// MarkPod refuses when the mark cannot be written or would not last: no
// ready instance, restart survival off (or never on with the gate), no
// kernel read-back, a plan without the section, a record of another cgroup.
func TestMarkPodRefusals(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		setup func(b *PrivilegeBackend, i *gateInstance)
		pod   sandboxpolicy.PodBinding
		want  string
	}{
		{name: "no instance", setup: func(b *PrivilegeBackend, _ *gateInstance) { b.instance = nil }, pod: gatePod(strictPlan), want: "no running instance"},
		{name: "instance not ready", setup: func(_ *PrivilegeBackend, i *gateInstance) { i.readyErr = errors.New("link detached") }, pod: gatePod(strictPlan), want: "not ready"},
		{name: "restart survival off", setup: func(b *PrivilegeBackend, _ *gateInstance) { b.pins, b.survivalOff = nil, errors.New("no boot id") }, pod: gatePod(strictPlan), want: "restart survival is off"},
		{name: "survival never enabled", setup: func(b *PrivilegeBackend, _ *gateInstance) { b.pins = nil }, pod: gatePod(strictPlan), want: "restart survival is off"},
		{name: "survival never enabled, gate on", setup: func(b *PrivilegeBackend, _ *gateInstance) { b.pins = nil; b.SetStartGate(true) }, pod: gatePod(strictPlan), want: "restart survival is off"},
		{name: "plan without the section", pod: gatePod(privPlan("", sandboxpolicy.CompiledPolicy{Identity: sandboxpolicy.PolicyIdentity{UID: "x"}, Mode: api.ModeEnforce})), want: "plan has no privilege section"},
		{name: "read-back fails", setup: func(_ *PrivilegeBackend, i *gateInstance) { i.readErr = errors.New("EIO") }, pod: gatePod(strictPlan), want: "EIO"},
		{name: "a record of another cgroup", setup: func(b *PrivilegeBackend, _ *gateInstance) {
			_ = b.MarkPod(ctx, testPodBinding("u", 99, strictPlan), seq(1, 1))
		}, pod: gatePod(strictPlan), want: "holds cgroup 99"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, e := newGate(t)
			i := e.last()
			if tt.setup != nil {
				tt.setup(b, i)
			}
			err := b.MarkPod(ctx, tt.pod, seq(2, 2))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("MarkPod: %v, want %q", err, tt.want)
			}
			if _, ok := i.entries[podCgroup]; ok {
				t.Fatal("a refused mark writes no entry")
			}
		})
	}
	// An instance without read-back cannot prove that no slot entry is
	// there: refused.
	pe := &fakePrivilegeEngine{}
	b, _ := NewPrivilege(pe, nil, "n")
	if err := b.Prepare(ctx, nil); err != nil {
		t.Fatal(err)
	}
	survive(b)
	if err := b.MarkPod(ctx, gatePod(strictPlan), seq(1, 1)); err == nil || !strings.Contains(err.Error(), "read its kernel bindings back") {
		t.Fatalf("no read-back: %v", err)
	}
}

// EnsurePodBound moves a pending mark to its own plan's slot with one map
// write, publishing the slot in place; it binds a pod whose containers
// started too, and it is sequence-neutral (lastSeq stays). A failed bind
// keeps the mark.
func TestEnsurePodBound(t *testing.T) {
	ctx := context.Background()
	b, e := newGate(t)
	i := e.last()
	started := gatePod(strictPlan)
	started.ContainersStarted = true
	if err := b.MarkPod(ctx, started, seq(5, 5)); err != nil {
		t.Fatal(err)
	}
	if len(i.published) != 0 {
		t.Fatal("the mark publishes nothing")
	}
	i.bindErr = map[uint64]error{podCgroup: errors.New("map full")}
	if err := b.EnsurePodBound(ctx, "u"); err == nil {
		t.Fatal("a failed bind must fail")
	}
	if p := b.pods["u"]; !p.pendingMark || i.entries[podCgroup].Slot != enforcement.PendingSlot {
		t.Fatalf("a failed bind keeps the mark: %+v %+v", p, i.entries[podCgroup])
	}
	i.bindErr = nil
	writes := i.binds[podCgroup]
	if err := b.EnsurePodBound(ctx, "u"); err != nil {
		t.Fatal(err)
	}
	key, _ := Combination(strictPlan)
	slot, ok := b.slots[key]
	p := b.pods["u"]
	if !ok || len(i.published) != 1 || p.pendingMark || p.lastSeq != seq(5, 5) || !p.sequenced || p.confirmed {
		t.Fatalf("bound: slot %v record %+v published %d", ok, p, len(i.published))
	}
	if entry := i.entries[podCgroup]; entry.Slot != slot || entry.Strict || i.binds[podCgroup]-writes != 1 {
		t.Fatalf("one write to the slot: %+v, writes %d", entry, i.binds[podCgroup]-writes)
	}
	if err := b.EnsurePodBound(ctx, "u"); err != nil || i.binds[podCgroup]-writes != 1 {
		t.Fatalf("a bound pod needs nothing: %v", err)
	}
	if err := b.EnsurePodBound(ctx, "other"); err == nil {
		t.Fatal("a pod with no record must fail")
	}
}

// ConfirmPod is Confirmed only for a bound pod of the caller's plan whose
// healthy slot reads back from the kernel; a pending mark that reads back is
// Pending; everything else is Faulted with its reason.
func TestConfirmPod(t *testing.T) {
	ctx := context.Background()
	bound := func(t *testing.T, b *PrivilegeBackend, i *gateInstance) {
		mustMark(t, b, strictPlan, seq(1, 1))
		if err := b.EnsurePodBound(ctx, "u"); err != nil {
			t.Fatal(err)
		}
	}
	pending := func(t *testing.T, b *PrivilegeBackend, i *gateInstance) { mustMark(t, b, auditPlan, seq(1, 1)) }
	slotOf := func(b *PrivilegeBackend) uint32 { key, _ := Combination(strictPlan); return b.slots[key] }
	tests := []struct {
		name   string
		setup  func(t *testing.T, b *PrivilegeBackend, i *gateInstance)
		plan   sandboxpolicy.Plan
		cgroup uint64
		state  sandboxpolicy.PodSectionState
		reason string
	}{
		{name: "bound", setup: bound, plan: strictPlan, state: sandboxpolicy.PodSectionConfirmed},
		{name: "Audit pending mark", setup: pending, plan: auditPlan, state: sandboxpolicy.PodSectionPending, reason: "pending mark"},
		{name: "Strict pending mark", setup: func(t *testing.T, b *PrivilegeBackend, _ *gateInstance) { mustMark(t, b, strictPlan, seq(1, 1)) },
			plan: strictPlan, state: sandboxpolicy.PodSectionPending, reason: "pending mark"},
		{name: "no record", plan: strictPlan, reason: "no pod binding"},
		{name: "stale plan", setup: bound, plan: strictPlan2, reason: "another plan"},
		{name: "another cgroup", setup: bound, plan: strictPlan, cgroup: 7, reason: "holds cgroup"},
		{name: "unhealthy slot", setup: func(t *testing.T, b *PrivilegeBackend, i *gateInstance) {
			bound(t, b, i)
			i.faults = map[uint32]uint64{slotOf(b): 1}
		}, plan: strictPlan, reason: "tracking fault"},
		{name: "instance not ready", setup: func(t *testing.T, b *PrivilegeBackend, i *gateInstance) {
			bound(t, b, i)
			i.readyErr = errors.New("link detached")
		}, plan: strictPlan, reason: "not ready"},
		{name: "read-back: another slot", setup: func(t *testing.T, b *PrivilegeBackend, i *gateInstance) {
			bound(t, b, i)
			e := i.entries[podCgroup]
			e.Slot++
			i.entries[podCgroup] = e
		}, plan: strictPlan, reason: "read-back"},
		{name: "read-back: a pending Audit mark still Strict", setup: func(t *testing.T, b *PrivilegeBackend, i *gateInstance) {
			pending(t, b, i)
			e := i.entries[podCgroup]
			e.Strict = true
			i.entries[podCgroup] = e
		}, plan: auditPlan, reason: "read-back"},
		{name: "read-back: no entry", setup: func(t *testing.T, b *PrivilegeBackend, i *gateInstance) {
			bound(t, b, i)
			delete(i.entries, podCgroup)
		}, plan: strictPlan, reason: "no entry"},
		{name: "read-back fails", setup: func(t *testing.T, b *PrivilegeBackend, i *gateInstance) {
			bound(t, b, i)
			i.readErr = errors.New("EIO")
		}, plan: strictPlan, reason: "EIO"},
		{name: "the mark's write into a new instance failed", setup: func(t *testing.T, b *PrivilegeBackend, i *gateInstance) {
			pending(t, b, i)
			b.pods["u"].bindPending = true
		}, plan: auditPlan, reason: "last bind"},
		{name: "being removed", setup: func(t *testing.T, b *PrivilegeBackend, i *gateInstance) {
			bound(t, b, i)
			b.pods["u"].pendingUnbind = true
		}, plan: strictPlan, reason: "being removed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, e := newGate(t)
			i := e.last()
			if tt.setup != nil {
				tt.setup(t, b, i)
			}
			cgroup := tt.cgroup
			if cgroup == 0 {
				cgroup = podCgroup
			}
			c := b.ConfirmPod("u", cgroup, tt.plan)
			if c.State != tt.state || !strings.Contains(c.Reason, tt.reason) || c.Section != sandboxpolicy.SectionPrivilege {
				t.Fatalf("ConfirmPod %+v, want state %v reason %q", c, tt.state, tt.reason)
			}
			if c.Strict != strictPolicies(tt.plan.Policies) {
				t.Fatalf("the class is the caller plan's: %+v", c)
			}
		})
	}
}

// A pending pod's status is faulted ("pending mark"), never read from per-slot
// counters, even when its target slot exists and is healthy.
func TestBoundPodPlansPendingIsFaulted(t *testing.T) {
	ctx := context.Background()
	b, e := newGate(t)
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{strictPlan}); err != nil {
		t.Fatal(err)
	}
	mustMark(t, b, strictPlan, seq(1, 1))
	i := e.last()
	i.health = 0
	confirmed, faulted := b.BoundPodPlans()
	if len(confirmed) != 0 || len(faulted) != 1 || i.health != 0 {
		t.Fatalf("pending: confirmed %d faulted %d, %d slot health reads", len(confirmed), len(faulted), i.health)
	}
	if err := b.EnsurePodBound(ctx, "u"); err != nil {
		t.Fatal(err)
	}
	if confirmed, faulted := b.BoundPodPlans(); len(confirmed) != 1 || len(faulted) != 0 {
		t.Fatalf("bound before its containers started: confirmed %d faulted %d", len(confirmed), len(faulted))
	}
}

// ReleasePod removes a pod's binding whatever the sequence (the pod's last
// sandbox is gone), and forgets the removal's order; without a record it
// removes the entry a previous run left on the cgroup. While the instance is
// not ready, the record waits for the unbind.
func TestReleasePod(t *testing.T) {
	ctx := context.Background()
	t.Run("pending, after a newer write", func(t *testing.T) {
		b, e := newGate(t)
		mustMark(t, b, strictPlan, seq(9, 9))
		if err := b.ReleasePod(ctx, "u", podCgroup); err != nil {
			t.Fatal(err)
		}
		if _, ok := e.last().entries[podCgroup]; ok || b.pods["u"] != nil {
			t.Fatal("released")
		}
		// A new sandbox of the pod starts over: any sequence marks it.
		mustMark(t, b, strictPlan, seq(1, 1))
	})
	t.Run("removed by sequence, then released", func(t *testing.T) {
		b, _ := newGate(t)
		removedAt(seq(9, 9))(t, b)
		if err := b.ReleasePod(ctx, "u", podCgroup); err != nil {
			t.Fatal(err)
		}
		mustMark(t, b, strictPlan, seq(1, 1))
	})
	t.Run("bound", func(t *testing.T) {
		b, e := newGate(t)
		mustMark(t, b, strictPlan, seq(1, 1))
		if err := b.EnsurePodBound(ctx, "u"); err != nil {
			t.Fatal(err)
		}
		if err := b.ReleasePod(ctx, "u", podCgroup); err != nil {
			t.Fatal(err)
		}
		if _, ok := e.last().entries[podCgroup]; ok || b.pods["u"] != nil || len(b.slots) != 0 {
			t.Fatalf("released, and the sweep frees the slot: %v", b.slots)
		}
	})
	t.Run("a previous run's entry", func(t *testing.T) {
		b, e := newGate(t)
		i := e.last()
		i.entries[podCgroup] = enforcement.Binding{Container: enforcement.ContainerIdentity{Runtime: podRuntime, ID: "u", CgroupID: podCgroup, CgroupPath: "/kubepods/podu"}, Slot: enforcement.PendingSlot, Strict: true}
		i.adopted[podCgroup] = true
		if err := b.ReleasePod(ctx, "u", podCgroup); err != nil {
			t.Fatal(err)
		}
		if _, ok := i.entries[podCgroup]; ok {
			t.Fatal("the adopted mark goes")
		}
	})
	t.Run("a previous run's policy entry stays", func(t *testing.T) {
		b, e := newGate(t)
		i := e.last()
		previous := enforcement.Binding{Container: enforcement.ContainerIdentity{Runtime: podRuntime, ID: "u", CgroupID: podCgroup}, Slot: 5, Subtree: true}
		i.entries[podCgroup], i.adopted[podCgroup] = previous, true
		if err := b.ReleasePod(ctx, "u", podCgroup); err != nil {
			t.Fatal(err)
		}
		if i.entries[podCgroup] != previous || !i.adopted[podCgroup] {
			t.Fatal("ReleasePod with no record removes only a pending mark, never a policy entry")
		}
	})
	t.Run("instance not ready", func(t *testing.T) {
		b, e := newGate(t)
		mustMark(t, b, strictPlan, seq(1, 1))
		e.last().readyErr = errors.New("link detached")
		if err := b.ReleasePod(ctx, "u", podCgroup); err == nil || !b.pods["u"].pendingUnbind {
			t.Fatalf("release waits: %v", err)
		}
		e.last().readyErr = nil
		// The next ready call unbinds it, also without a sequence.
		if err := b.BindPods(ctx, nil); err != nil || b.pods["u"] != nil {
			t.Fatalf("the pending unbind: %v %+v", err, b.pods["u"])
		}
	})
}

// BindPods and BindPodsAt on start gate records:
//   - missing from the input never removes a marked pod (missing is not
//     Unselected), whatever the sequence;
//   - a plan without the section (an authoritative un-selection), a
//     loosening or another plan applies only at an admitted sequence, and a
//     refusal is an ErrStaleSequence error for that pod with BindPodsAt
//     while the other pods proceed;
//   - BindPods (no sequence) only raises a marked pod (Audit to Strict), and
//     its refusals are counted, never errors;
//   - a pending mark moves to its own plan's slot at any sequence, and
//     lastSeq never goes down.
func TestBindPodsOrdersStartGateRecords(t *testing.T) {
	ctx := context.Background()
	other := testPodBinding("other", 200, strictPlan)
	unselected := []sandboxpolicy.PodBinding{gatePod(privPlan("", sandboxpolicy.CompiledPolicy{Identity: sandboxpolicy.PolicyIdentity{UID: "x"}}))}
	tests := []struct {
		name string
		// mark is the record's plan, marked at (5, 5); bound binds it.
		mark  sandboxpolicy.Plan
		bound bool
		pods  []sandboxpolicy.PodBinding
		seq   *sandboxpolicy.Seq
		stale bool
		// want: "absent", "pending", or "bound"; strict is the record's
		// class, lastSeq its order after the call.
		want    string
		strict  bool
		lastSeq sandboxpolicy.Seq
	}{
		{name: "missing, newer: kept", mark: strictPlan, seq: ptrSeq(9, 9), want: "pending", strict: true, lastSeq: seq(5, 5)},
		{name: "missing, bound, newer: kept", mark: strictPlan, bound: true, seq: ptrSeq(9, 9), want: "bound", strict: true, lastSeq: seq(5, 5)},
		{name: "missing, no sequence: kept", mark: strictPlan, want: "pending", strict: true, lastSeq: seq(5, 5)},
		{name: "unselected, newer: unbound", mark: strictPlan, pods: unselected, seq: ptrSeq(6, 6), want: "absent"},
		{name: "unselected, equal: refused", mark: strictPlan, pods: unselected, seq: ptrSeq(5, 5), stale: true, want: "pending", strict: true, lastSeq: seq(5, 5)},
		{name: "unselected, older: refused", mark: strictPlan, pods: unselected, seq: ptrSeq(4, 4), stale: true, want: "pending", strict: true, lastSeq: seq(5, 5)},
		{name: "unselected, incomparable: refused", mark: strictPlan, pods: unselected, seq: ptrSeq(6, 4), stale: true, want: "pending", strict: true, lastSeq: seq(5, 5)},
		{name: "unselected, no sequence: kept, no error", mark: strictPlan, pods: unselected, want: "pending", strict: true, lastSeq: seq(5, 5)},
		{name: "unselected, bound, equal: refused", mark: strictPlan, bound: true, pods: unselected, seq: ptrSeq(5, 5), stale: true, want: "bound", strict: true, lastSeq: seq(5, 5)},
		{name: "unselected, bound, newer: unbound", mark: strictPlan, bound: true, pods: unselected, seq: ptrSeq(6, 5), want: "absent"},
		{name: "same plan, older: bound (sequence-neutral)", mark: strictPlan, pods: []sandboxpolicy.PodBinding{gatePod(strictPlan)}, seq: ptrSeq(1, 1), want: "bound", strict: true, lastSeq: seq(5, 5)},
		{name: "same plan, no sequence: bound", mark: auditPlan, pods: []sandboxpolicy.PodBinding{gatePod(auditPlan)}, want: "bound", lastSeq: seq(5, 5)},
		{name: "same plan, newer: bound, order moves on", mark: strictPlan, pods: []sandboxpolicy.PodBinding{gatePod(strictPlan)}, seq: ptrSeq(8, 8), want: "bound", strict: true, lastSeq: seq(8, 8)},
		{name: "Strict to Audit, equal: refused", mark: strictPlan, pods: []sandboxpolicy.PodBinding{gatePod(auditPlan)}, seq: ptrSeq(5, 5), stale: true, want: "pending", strict: true, lastSeq: seq(5, 5)},
		{name: "Strict to Audit, newer: bound to Audit", mark: strictPlan, pods: []sandboxpolicy.PodBinding{gatePod(auditPlan)}, seq: ptrSeq(6, 6), want: "bound", lastSeq: seq(6, 6)},
		{name: "Strict to Audit, no sequence: kept, no error", mark: strictPlan, pods: []sandboxpolicy.PodBinding{gatePod(auditPlan)}, want: "pending", strict: true, lastSeq: seq(5, 5)},
		{name: "Audit to Strict, equal: bound to Strict", mark: auditPlan, pods: []sandboxpolicy.PodBinding{gatePod(strictPlan)}, seq: ptrSeq(5, 5), want: "bound", strict: true, lastSeq: seq(5, 5)},
		{name: "Audit to Strict, older: refused", mark: auditPlan, pods: []sandboxpolicy.PodBinding{gatePod(strictPlan)}, seq: ptrSeq(5, 4), stale: true, want: "pending", lastSeq: seq(5, 5)},
		{name: "Audit to Strict, no sequence: bound to Strict (a raise)", mark: auditPlan, pods: []sandboxpolicy.PodBinding{gatePod(strictPlan)}, want: "bound", strict: true, lastSeq: seq(5, 5)},
		{name: "bound Audit to Strict, no sequence: moved (a raise)", mark: auditPlan, bound: true, pods: []sandboxpolicy.PodBinding{gatePod(strictPlan)}, want: "bound", strict: true, lastSeq: seq(5, 5)},
		{name: "Strict to another Strict, no sequence: kept", mark: strictPlan, pods: []sandboxpolicy.PodBinding{gatePod(strictPlan2)}, want: "pending", strict: true, lastSeq: seq(5, 5)},
		{name: "bound, Strict to Audit, equal: refused", mark: strictPlan, bound: true, pods: []sandboxpolicy.PodBinding{gatePod(auditPlan)}, seq: ptrSeq(5, 5), stale: true, want: "bound", strict: true, lastSeq: seq(5, 5)},
		{name: "empty plan keeps the mark", mark: strictPlan, pods: []sandboxpolicy.PodBinding{gatePod(sandboxpolicy.Plan{})}, want: "pending", strict: true, lastSeq: seq(5, 5)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, e := newGate(t)
			i := e.last()
			// Every plan's slot is ready, so a wanted pod can bind.
			if err := b.Prepare(ctx, []sandboxpolicy.Plan{strictPlan, strictPlan2, auditPlan}); err != nil {
				t.Fatal(err)
			}
			mustMark(t, b, tt.mark, seq(5, 5))
			if tt.bound {
				if err := b.EnsurePodBound(ctx, "u"); err != nil {
					t.Fatal(err)
				}
			}
			pods := append([]sandboxpolicy.PodBinding{other}, tt.pods...)
			var err error
			if tt.seq == nil {
				err = b.BindPods(ctx, pods)
			} else {
				err = b.BindPodsAt(ctx, pods, *tt.seq)
			}
			if tt.stale != errors.Is(err, sandboxpolicy.ErrStaleSequence) || (!tt.stale && err != nil) {
				t.Fatalf("bind: %v, stale %v", err, tt.stale)
			}
			if tt.stale && !strings.Contains(err.Error(), "pod ns/u") {
				t.Fatalf("the error names the pod: %v", err)
			}
			if _, ok := i.entries[200]; !ok || b.pods["other"] == nil {
				t.Fatal("the other pod proceeds")
			}
			if len(tt.pods) == 0 && b.absentKept != 1 {
				t.Fatalf("a kept missing pod is counted: %d", b.absentKept)
			}
			p, entry := b.pods["u"], i.entries[podCgroup]
			switch tt.want {
			case "absent":
				if _, ok := i.entries[podCgroup]; ok || p != nil {
					t.Fatalf("removed: record %+v entry %+v", p, entry)
				}
				if _, ok := b.removed[podCgroup]; !ok {
					t.Fatal("the removal's order is kept")
				}
				return
			case "pending":
				if p == nil || !p.pendingMark || entry.Slot != enforcement.PendingSlot || entry.Strict != tt.strict {
					t.Fatalf("pending: record %+v entry %+v", p, entry)
				}
			case "bound":
				if p == nil || p.pendingMark || entry.Slot == enforcement.PendingSlot || b.slots[p.combination] != entry.Slot {
					t.Fatalf("bound: record %+v entry %+v", p, entry)
				}
				policies := b.combinations[p.combination]
				if strictPolicies(policies) != tt.strict {
					t.Fatalf("bound to the class %v, want %v", strictPolicies(policies), tt.strict)
				}
			}
			if !p.sequenced || p.lastSeq != tt.lastSeq {
				t.Fatalf("order %+v, want %v", p, tt.lastSeq)
			}
		})
	}
}

func ptrSeq(config, epoch uint64) *sandboxpolicy.Seq {
	s := seq(config, epoch)
	return &s
}

// An un-selection while the instance is not ready keeps the pending mark
// until the next ready call (pendingUnbind), which removes it without asking
// the order again, even when the next input misses the pod; a pending mark is
// never confused with a pending bind (it has a kernel identity to remove).
func TestBindPodsUnbindsAPendingMarkAtTheNextReadyCall(t *testing.T) {
	ctx := context.Background()
	b, e := newGate(t)
	i := e.last()
	mustMark(t, b, strictPlan, seq(5, 5))
	i.readyErr = errors.New("link detached")
	unselected := gatePod(privPlan("", sandboxpolicy.CompiledPolicy{Identity: sandboxpolicy.PolicyIdentity{UID: "x"}}))
	if err := b.BindPodsAt(ctx, []sandboxpolicy.PodBinding{unselected}, seq(6, 6)); err != nil {
		t.Fatal(err)
	}
	if p := b.pods["u"]; p == nil || !p.pendingUnbind || p.lastSeq != seq(6, 6) {
		t.Fatalf("kept until ready: %+v", p)
	}
	if _, ok := i.entries[podCgroup]; !ok {
		t.Fatal("the mark stays while the instance is not ready")
	}
	i.readyErr = nil
	if err := b.BindPods(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := i.entries[podCgroup]; ok || b.pods["u"] != nil {
		t.Fatal("the next ready call removes the mark")
	}
	if err := b.MarkPod(ctx, gatePod(strictPlan), seq(5, 5)); !errors.Is(err, sandboxpolicy.ErrStaleSequence) {
		t.Fatalf("a mark older than the removal: %v", err)
	}
}

// UnmarkPod removes a start gate pod only at a strictly newer sequence, keeps
// the removal's order (a stale mark or bind is refused after it), and never
// removes a record main bound.
func TestUnmarkPod(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		seq    sandboxpolicy.Seq
		bound  bool
		remove bool
	}{
		{name: "newer", seq: seq(6, 6), remove: true},
		{name: "newer, bound", seq: seq(5, 6), bound: true, remove: true},
		{name: "equal", seq: seq(5, 5)},
		{name: "older", seq: seq(4, 4)},
		{name: "incomparable", seq: seq(6, 4)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, e := newGate(t)
			mustMark(t, b, strictPlan, seq(5, 5))
			if tt.bound {
				if err := b.EnsurePodBound(ctx, "u"); err != nil {
					t.Fatal(err)
				}
			}
			err := b.UnmarkPod(ctx, "u", podCgroup, tt.seq)
			_, entry := e.last().entries[podCgroup]
			if tt.remove != (err == nil) || tt.remove == entry || tt.remove == (b.pods["u"] != nil) {
				t.Fatalf("UnmarkPod: %v, entry %v record %+v", err, entry, b.pods["u"])
			}
			if !tt.remove && !errors.Is(err, sandboxpolicy.ErrStaleSequence) {
				t.Fatalf("a refusal is ErrStaleSequence: %v", err)
			}
			if tt.remove {
				if err := b.MarkPod(ctx, gatePod(strictPlan), seq(5, 5)); !errors.Is(err, sandboxpolicy.ErrStaleSequence) {
					t.Fatalf("a mark older than the removal: %v", err)
				}
				if err := b.BindPodsAt(ctx, []sandboxpolicy.PodBinding{gatePod(strictPlan)}, seq(5, 5)); !errors.Is(err, sandboxpolicy.ErrStaleSequence) || b.pods["u"] != nil {
					t.Fatalf("a bind older than the removal: %v", err)
				}
			}
		})
	}
	t.Run("main's record", func(t *testing.T) {
		b, _ := newGate(t)
		if err := b.Prepare(ctx, []sandboxpolicy.Plan{strictPlan}); err != nil {
			t.Fatal(err)
		}
		if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{gatePod(strictPlan)}); err != nil {
			t.Fatal(err)
		}
		if err := b.UnmarkPod(ctx, "u", podCgroup, seq(9, 9)); err == nil || b.pods["u"] == nil {
			t.Fatalf("not a start gate binding: %v", err)
		}
	})
}

// A pod that BindPodsAt binds first is ordered from its sequence: a later
// MarkPod or un-selection at an older sequence is refused.
func TestBindPodsAtSequencesNewRecords(t *testing.T) {
	ctx := context.Background()
	b, _ := newGate(t)
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{strictPlan}); err != nil {
		t.Fatal(err)
	}
	if err := b.BindPodsAt(ctx, []sandboxpolicy.PodBinding{gatePod(strictPlan)}, seq(7, 7)); err != nil {
		t.Fatal(err)
	}
	if p := b.pods["u"]; p == nil || !p.sequenced || p.lastSeq != seq(7, 7) || !p.strict {
		t.Fatalf("record %+v", p)
	}
	if err := b.UnmarkPod(ctx, "u", podCgroup, seq(7, 7)); !errors.Is(err, sandboxpolicy.ErrStaleSequence) {
		t.Fatalf("an equal un-selection: %v", err)
	}
}

// A failed move of a sequenced pod records the target as a failed bind (not a
// mark): status reports it faulted, never the new plan as confirmed, and a
// later bind binds the target.
func TestFailedSequencedMoveRecordsTheTarget(t *testing.T) {
	ctx := context.Background()
	b, e := newGate(t)
	i := e.last()
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{strictPlan, auditPlan}); err != nil {
		t.Fatal(err)
	}
	mustMark(t, b, auditPlan, seq(5, 5))
	if err := b.EnsurePodBound(ctx, "u"); err != nil {
		t.Fatal(err)
	}
	moved := testPodBinding("u", podCgroup+1, strictPlan)
	i.bindErr = map[uint64]error{podCgroup + 1: errors.New("map full")}
	if err := b.BindPodsAt(ctx, []sandboxpolicy.PodBinding{moved}, seq(6, 6)); err == nil {
		t.Fatal("the bind fails")
	}
	key, _ := Combination(strictPlan)
	p := b.pods["u"]
	if p.pendingMark || !p.bindPending || p.combination != key || !p.strict || p.pod.CgroupID != podCgroup+1 {
		t.Fatalf("record %+v", p)
	}
	if confirmed, faulted := b.BoundPodPlans(); len(confirmed) != 0 || len(faulted) != 1 {
		t.Fatalf("status: confirmed %d faulted %d", len(confirmed), len(faulted))
	}
	if c := b.ConfirmPod("u", podCgroup+1, strictPlan); c.State == sandboxpolicy.PodSectionConfirmed {
		t.Fatalf("ConfirmPod %+v", c)
	}
	i.bindErr = nil
	if err := b.EnsurePodBound(ctx, "u"); err != nil {
		t.Fatal(err)
	}
	if entry := i.entries[podCgroup+1]; entry.Slot != b.slots[key] {
		t.Fatalf("the target is bound: %+v", entry)
	}
	if c := b.ConfirmPod("u", podCgroup+1, strictPlan); c.State != sandboxpolicy.PodSectionConfirmed {
		t.Fatalf("ConfirmPod %+v", c)
	}
}

// A replacement carries a pending mark as a mark (PendingSlot, its class),
// never as its target slot: in place (a new instance on the same state) and
// with a new instance's initial bindings.
func TestReplacementCarriesAPendingMark(t *testing.T) {
	ctx := context.Background()
	t.Run("in place", func(t *testing.T) {
		b, e := newGate(t)
		mustMark(t, b, strictPlan, seq(1, 1))
		e.last().readyErr = errors.New("link detached")
		if err := b.Prepare(ctx, nil); err != nil || len(e.instances) != 2 {
			t.Fatalf("heal: %v instances %d", err, len(e.instances))
		}
		i := e.last()
		entry, p := i.entries[podCgroup], b.pods["u"]
		if entry.Slot != enforcement.PendingSlot || !entry.Strict || i.adopted[podCgroup] || !p.pendingMark || p.bindPending || p.confirmed {
			t.Fatalf("carried: entry %+v adopted %v record %+v", entry, i.adopted[podCgroup], p)
		}
		// The target's slot is published by the start (the pod comes
		// before speculation), and kept by the sweep.
		key, _ := Combination(strictPlan)
		if _, ok := b.slots[key]; !ok {
			t.Fatal("the mark's plan is wanted")
		}
	})
	t.Run("a failed carry keeps the state's entry until the mark is written", func(t *testing.T) {
		b, e := newGate(t)
		mustMark(t, b, strictPlan, seq(1, 1))
		e.last().readyErr = errors.New("link detached")
		old := e.last()
		// The next instance refuses the pod's bind.
		e.onStart = func(i *gateInstance) { i.bindErr = map[uint64]error{podCgroup: errors.New("map full")} }
		if err := b.Prepare(ctx, nil); err != nil {
			t.Fatal(err)
		}
		i := e.last()
		if i == old || !b.pods["u"].bindPending || !i.adopted[podCgroup] || !i.entries[podCgroup].Strict {
			t.Fatalf("the state's mark stays adopted: %+v adopted %v", b.pods["u"], i.adopted[podCgroup])
		}
		if err := b.Prepare(ctx, nil); err != nil {
			t.Fatal(err)
		}
		if _, ok := i.entries[podCgroup]; !ok {
			t.Fatal("the sweep must not drop the state's mark while the pod's mark is unwritten")
		}
		i.bindErr = nil
		if err := b.MarkPod(ctx, gatePod(strictPlan), seq(1, 1)); err != nil || b.pods["u"].bindPending || i.adopted[podCgroup] {
			t.Fatalf("a mark writes it again: %v %+v", err, b.pods["u"])
		}
	})
	t.Run("new instance", func(t *testing.T) {
		b, e := newGate(t)
		mustMark(t, b, strictPlan, seq(1, 1))
		b.section.inPlace = false
		e.last().readyErr = errors.New("link detached")
		if err := b.Prepare(ctx, nil); err != nil || len(e.instances) != 2 {
			t.Fatalf("replace: %v instances %d", err, len(e.instances))
		}
		var carried *enforcement.Binding
		for _, ib := range e.configs[1].InitialBindings {
			if ib.Container.CgroupID == podCgroup {
				carried = &ib
			}
		}
		if carried == nil || carried.Slot != enforcement.PendingSlot || !carried.Strict || !b.pods["u"].pendingMark {
			t.Fatalf("initial binding %+v", carried)
		}
	})
}

// The record's class answers the restart readers for a pending pod
// (currentStrict), and its plan keeps its slot wanted.
func TestPendingRecordReaders(t *testing.T) {
	b, _ := newGate(t)
	mustMark(t, b, auditPlan, seq(1, 1))
	if strict, ok := b.currentStrict(podCgroup); !ok || strict {
		t.Fatalf("Audit pending: %v %v", strict, ok)
	}
	if err := b.MarkPod(context.Background(), gatePod(strictPlan), seq(2, 2)); err != nil {
		t.Fatal(err)
	}
	if strict, ok := b.currentStrict(podCgroup); !ok || !strict {
		t.Fatalf("Strict pending: %v %v", strict, ok)
	}
	key, policies := Combination(strictPlan)
	if got := b.wanted(nil, nil, nil, b.pods); len(got[key]) != len(policies) {
		t.Fatalf("the pending plan is wanted with its policies: %v", got)
	}
}

// SetNRISynced records a completion (nil proven: synced, nothing proven);
// SetNRIDisconnected clears it, and a completion at or below the last
// disconnect's epoch is stale (the dying connection's late completion).
func TestSetNRISyncedEpoch(t *testing.T) {
	b, _ := newGate(t)
	b.SetNRISynced(2, map[uint64]bool{7: true})
	if b.nriEpoch != 2 || !b.nriProven[7] {
		t.Fatalf("synced: %d %v", b.nriEpoch, b.nriProven)
	}
	b.SetNRIDisconnected(2) // the connection closed
	if b.nriProven != nil {
		t.Fatalf("disconnect: %v", b.nriProven)
	}
	b.SetNRISynced(2, map[uint64]bool{8: true}) // its late completion
	if b.nriProven != nil {
		t.Fatalf("a completion at the disconnect's epoch is stale: %v", b.nriProven)
	}
	b.SetNRISynced(1, map[uint64]bool{8: true})
	if b.nriProven != nil {
		t.Fatalf("a completion below it is stale: %v", b.nriProven)
	}
	b.SetNRISynced(3, nil) // the next connection: synced, nothing proven
	if b.nriEpoch != 3 || b.nriProven == nil || len(b.nriProven) != 0 {
		t.Fatalf("nil proven is a completion, not a disconnect: %d %v", b.nriEpoch, b.nriProven)
	}
	b.SetNRISynced(4, map[uint64]bool{})
	b.SetNRISynced(3, map[uint64]bool{9: true}) // a late completion of an older connection
	if b.nriEpoch != 4 || b.nriProven[9] {
		t.Fatalf("a completion older than the last one is stale: %d %v", b.nriEpoch, b.nriProven)
	}
	b.SetNRIDisconnected(1) // an older disconnect does not lower the bound
	b.SetNRISynced(2, map[uint64]bool{})
	if b.nriEpoch != 4 {
		t.Fatalf("still stale at epoch 2: %d", b.nriEpoch)
	}
}

// The sweep forgets the removal order of a gone cgroup (no pod can be
// marked there again), and keeps the others.
func TestSweepPrunesRemovalsOfGoneCgroups(t *testing.T) {
	ctx := context.Background()
	b, _ := newGate(t)
	b.removed = map[uint64]sandboxpolicy.Seq{podCgroup: seq(5, 5), 200: seq(5, 5)}
	b.sweeps = 0
	calls := 0
	b.SetCgroupGone(func(cgroup uint64) bool { calls++; return cgroup == podCgroup })
	for n := 1; n < removedPruneEvery; n++ {
		if err := b.BindPods(ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 0 {
		t.Fatalf("the gone proof (I/O) runs at most once per %d sweeps: %d calls", removedPruneEvery, calls)
	}
	if err := b.BindPods(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.removed[podCgroup]; ok {
		t.Fatal("a gone cgroup's removal is forgotten")
	}
	if _, ok := b.removed[200]; !ok {
		t.Fatal("a live cgroup's removal is kept")
	}
}

// The native instance is a NodeInstance, so the owner reaches Rebind and its
// slot gate (S1 review finding 5).
var _ NodeInstance = (*nativeNodeInstance)(nil)

// S2 review v2, finding 2: a start gate pod missing from the input stays,
// unless its cgroup is proven gone; then it is removed whatever the
// sequence (none needed), and no removal order is kept for the gone cgroup.
func TestBindPodsRemovesAMissingPodOfAGoneCgroup(t *testing.T) {
	ctx := context.Background()
	b, e := newGate(t)
	mustMark(t, b, strictPlan, seq(5, 5))
	b.SetCgroupGone(func(cgroup uint64) bool { return false })
	if err := b.BindPods(ctx, nil); err != nil || b.pods["u"] == nil || b.absentKept != 1 {
		t.Fatalf("a live missing pod stays: %v %+v", err, b.pods["u"])
	}
	b.SetCgroupGone(func(cgroup uint64) bool { return cgroup == podCgroup })
	// The gone proof is I/O: checked once every removedPruneEvery calls.
	b.binds = 0
	for n := 1; n < removedPruneEvery; n++ {
		if err := b.BindPods(ctx, nil); err != nil || b.pods["u"] == nil {
			t.Fatalf("call %d checks no gone proof: %v", n, err)
		}
	}
	if err := b.BindPods(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.last().entries[podCgroup]; ok || b.pods["u"] != nil {
		t.Fatal("a gone cgroup's pod is removed")
	}
	if _, ok := b.removed[podCgroup]; ok {
		t.Fatal("no order is kept for a gone cgroup")
	}
}

// S2 review v2, LOW 6: a pod released while the instance was not ready only
// waits for its unbind: a later call without a sequence that lists it (even
// with a looser plan) neither takes it back nor binds it.
func TestReleasedPodOnlyUnbinds(t *testing.T) {
	ctx := context.Background()
	b, e := newGate(t)
	if err := b.Prepare(ctx, []sandboxpolicy.Plan{strictPlan, auditPlan}); err != nil {
		t.Fatal(err)
	}
	mustMark(t, b, strictPlan, seq(5, 5))
	i := e.last()
	i.readyErr = errors.New("link detached")
	if err := b.ReleasePod(ctx, "u", podCgroup); err == nil || !b.pods["u"].released {
		t.Fatalf("release pending: %v", err)
	}
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{gatePod(auditPlan)}); err != nil {
		t.Fatal(err)
	}
	if p := b.pods["u"]; p == nil || !p.pendingUnbind || !p.pendingMark {
		t.Fatalf("not ready: the release waits, untouched: %+v", p)
	}
	i.readyErr = nil
	if err := b.BindPods(ctx, []sandboxpolicy.PodBinding{gatePod(auditPlan)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := i.entries[podCgroup]; ok || b.pods["u"] != nil {
		t.Fatalf("the released pod is unbound, not bound to the Audit plan: %+v %+v", b.pods["u"], i.entries[podCgroup])
	}
}

// S2 review v3, finding 3 (lead decision): UnmarkPod with no record only
// records the removal's order; it never drops a previous run's mark on the
// cgroup, on the first call or any later one (keepPending decides it). A
// stale call is refused, and a released record's removal returns nil.
func TestUnmarkPodWithoutARecord(t *testing.T) {
	ctx := context.Background()
	b, e := newGate(t)
	i := e.last()
	i.entries[podCgroup] = enforcement.Binding{Container: enforcement.ContainerIdentity{Runtime: podRuntime, ID: "old", CgroupID: podCgroup}, Slot: enforcement.PendingSlot, Strict: true}
	i.adopted[podCgroup] = true
	for n, s := range []sandboxpolicy.Seq{seq(5, 5), seq(6, 6)} {
		if err := b.UnmarkPod(ctx, "u", podCgroup, s); err != nil {
			t.Fatalf("call %d: %v", n+1, err)
		}
		if _, ok := i.entries[podCgroup]; !ok {
			t.Fatalf("call %d dropped the adopted mark", n+1)
		}
		if b.removed[podCgroup] != s {
			t.Fatalf("call %d: the order is recorded: %v", n+1, b.removed[podCgroup])
		}
	}
	if err := b.UnmarkPod(ctx, "u", podCgroup, seq(6, 6)); !errors.Is(err, sandboxpolicy.ErrStaleSequence) {
		t.Fatalf("an equal sequence is stale: %v", err)
	}
	if err := b.MarkPod(ctx, gatePod(strictPlan), seq(6, 5)); !errors.Is(err, sandboxpolicy.ErrStaleSequence) {
		t.Fatalf("a mark older than the removal: %v", err)
	}
	t.Run("released", func(t *testing.T) {
		b, e := newGate(t)
		mustMark(t, b, strictPlan, seq(5, 5))
		e.last().readyErr = errors.New("link detached")
		if err := b.ReleasePod(ctx, "u", podCgroup); err == nil {
			t.Fatal("release pending")
		}
		if err := b.UnmarkPod(ctx, "u", podCgroup, seq(9, 9)); err != nil {
			t.Fatalf("a released pod's removal is under way: %v", err)
		}
	})
}
