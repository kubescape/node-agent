// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// parentIdentity is a parent cgroup marked before its containers start;
// containerInParent is a container that runs in that same cgroup (it shares
// the cgroup ID).
var (
	parentIdentity    = ContainerIdentity{Runtime: "parent", ID: "uid-1", CgroupID: 42, CgroupPath: "/workloads.slice/parent-uid-1"}
	containerInParent = ContainerIdentity{Runtime: "containerd", ID: "c1", CgroupID: 42, CgroupPath: "/workloads.slice/parent-uid-1"}
)

// pendingMark is the parent cgroup mark of a start gate: PendingSlot, Subtree and
// RuntimeHelpers, with its own class.
func pendingMark(strict bool) Binding {
	return Binding{Container: parentIdentity, Slot: PendingSlot, Strict: strict, Subtree: true, RuntimeHelpers: true}
}

// puts counts the binding map writes in the fixture's log.
func puts(log []string) int {
	n := 0
	for _, l := range log {
		if l == "put bindings" {
			n++
		}
	}
	return n
}

// validate takes the class of a real slot from the slot only, and exempts
// PendingSlot from the range check.
func TestValidatePendingSlot(t *testing.T) {
	f := newPublishFixture(t)
	tests := []struct {
		name    string
		binding Binding
		wantErr string
	}{
		{name: "Strict pending", binding: pendingMark(true)},
		{name: "Audit pending", binding: pendingMark(false)},
		{name: "exact Audit pending", binding: Binding{Container: parentIdentity, Slot: PendingSlot}},
		{name: "real slot", binding: Binding{Container: parentIdentity, Slot: 1}},
		{name: "Strict on a real slot", binding: Binding{Container: parentIdentity, Slot: 1, Strict: true}, wantErr: "only a pending binding carries its own class"},
		{name: "Strict on slot 0", binding: Binding{Container: parentIdentity, Slot: 0, Strict: true}, wantErr: "only a pending binding carries its own class"},
		{name: "out of range", binding: Binding{Container: parentIdentity, Slot: 4}, wantErr: "out of range"},
		{name: "one below PendingSlot", binding: Binding{Container: parentIdentity, Slot: PendingSlot - 1}, wantErr: "out of range"},
		{name: "pending runtime helpers without subtree", binding: Binding{Container: parentIdentity, Slot: PendingSlot, RuntimeHelpers: true}, wantErr: "subtree"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.b.mu.Lock()
			err := f.b.validate(tt.binding)
			f.b.mu.Unlock()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("validate: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("validate: %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// A pending binding needs no published slot (there is none); a real slot
// still does.
func TestBindPendingSlotNeedsNoPublication(t *testing.T) {
	f := newPublishFixture(t)
	if err := f.b.Bind(Binding{Container: parentIdentity, Slot: 2}); err == nil || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("a bind to an unpublished real slot: %v", err)
	}
	if err := f.b.Bind(pendingMark(true)); err != nil {
		t.Fatalf("a pending bind: %v", err)
	}
	if v := f.members.data[parentIdentity.CgroupID].(bindingValue); v.Slot != PendingSlot {
		t.Fatalf("pending entry: %+v", v)
	}
}

// The kernel value of a pending binding carries its own class, whatever the
// configured class of the (missing) slot is: the fixture's StrictSlot says
// Audit for every slot.
func TestPendingSlotFlags(t *testing.T) {
	tests := []struct {
		name    string
		binding Binding
		checked bool
		want    bindingValue
	}{
		{name: "Strict mark", binding: pendingMark(true), want: bindingValue{Slot: PendingSlot, Flags: bindingStrict | bindingSubtree | bindingRuntimeHelpers}},
		{name: "Strict mark, checked", binding: pendingMark(true), checked: true, want: bindingValue{Slot: PendingSlot, Flags: bindingStrict | bindingSubtree | bindingRuntimeHelpers | bindingRingChecked}},
		{name: "Audit mark", binding: pendingMark(false), want: bindingValue{Slot: PendingSlot, Flags: bindingSubtree | bindingRuntimeHelpers}},
		{name: "Audit mark, checked", binding: pendingMark(false), checked: true, want: bindingValue{Slot: PendingSlot, Flags: bindingSubtree | bindingRuntimeHelpers}},
		{name: "exact Strict", binding: Binding{Container: parentIdentity, Slot: PendingSlot, Strict: true}, want: bindingValue{Slot: PendingSlot, Flags: bindingStrict}},
		{name: "exact Audit", binding: Binding{Container: parentIdentity, Slot: PendingSlot}, want: bindingValue{Slot: PendingSlot}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPublishFixture(t)
			f.b.mu.Lock()
			value, kernel := f.b.value(tt.binding), f.b.kernelValue(tt.binding, tt.checked)
			f.b.mu.Unlock()
			if kernel != tt.want {
				t.Fatalf("kernelValue %+v, want %+v", kernel, tt.want)
			}
			if want := (bindingValue{Slot: tt.want.Slot, Flags: tt.want.Flags &^ bindingRingChecked}); value != want {
				t.Fatalf("value %+v, want %+v", value, want)
			}
			if got := f.b.ClassOf(tt.binding); got != tt.binding.Strict {
				t.Fatalf("ClassOf %v, want %v", got, tt.binding.Strict)
			}
			// Bind writes the same value (no walk in this fixture).
			if err := f.b.Bind(tt.binding); err != nil {
				t.Fatal(err)
			}
			if got := f.members.data[parentIdentity.CgroupID].(bindingValue); got != value {
				t.Fatalf("bound entry %+v, want %+v", got, value)
			}
		})
	}
}

// THE FLIP TEST: a parent cgroup bound from a Strict pending mark to a real Strict slot
// takes the slot's class there; a later in-place Strict->Audit flip of that
// slot leaves no BINDING_STRICT on it.
func TestPendingToSlotThenAuditFlipDropsStrict(t *testing.T) {
	f := newPublishFixture(t)
	if err := f.b.Publish(f.publication(2, 10, true)); err != nil {
		t.Fatal(err)
	}
	if err := f.b.Bind(pendingMark(true)); err != nil {
		t.Fatal(err)
	}
	if v := f.members.data[parentIdentity.CgroupID].(bindingValue); v != (bindingValue{Slot: PendingSlot, Flags: bindingStrict | bindingSubtree | bindingRuntimeHelpers}) {
		t.Fatalf("Strict pending mark: %+v", v)
	}
	// The class of a real slot is the slot's: a bound binding never carries
	// Strict itself.
	if err := f.b.Bind(Binding{Container: parentIdentity, Slot: 2, Strict: true, Subtree: true, RuntimeHelpers: true}); err == nil {
		t.Fatal("a Strict class on a real slot must be refused")
	}
	before := puts(*f.members.log)
	bound := Binding{Container: parentIdentity, Slot: 2, Subtree: true, RuntimeHelpers: true}
	if err := f.b.Bind(bound); err != nil {
		t.Fatal(err)
	}
	if n := puts(*f.members.log) - before; n != 1 {
		t.Fatalf("pending -> bound must be one map write, got %d", n)
	}
	if v := f.members.data[parentIdentity.CgroupID].(bindingValue); v != (bindingValue{Slot: 2, Flags: bindingStrict | bindingSubtree | bindingRuntimeHelpers}) {
		t.Fatalf("bound to a Strict slot: %+v", v)
	}
	// Strict -> Audit in place (slots.go publishSlot -> rewriteClass).
	f.clock = f.clock.Add(DefaultQuarantine)
	if err := f.b.Publish(f.publication(2, 11, false)); err != nil {
		t.Fatal(err)
	}
	if v := f.members.data[parentIdentity.CgroupID].(bindingValue); v.Flags&bindingStrict != 0 || v != (bindingValue{Slot: 2, Flags: bindingSubtree | bindingRuntimeHelpers}) {
		t.Fatalf("after the Audit flip the binding must not be Strict: %+v", v)
	}
	if f.b.ClassOf(bound) {
		t.Fatal("ClassOf must follow the slot after the flip")
	}
	if kept, strict := f.b.Kept(parentIdentity.CgroupID); !kept || strict {
		t.Fatalf("Kept after the flip: %v %v", kept, strict)
	}
	// A refresh re-bind writes nothing new and stays Audit.
	if err := f.b.Bind(bound); err != nil {
		t.Fatal(err)
	}
	if v := f.members.data[parentIdentity.CgroupID].(bindingValue); v.Flags&bindingStrict != 0 {
		t.Fatalf("re-bind after the flip: %+v", v)
	}
}

// rewriteClass (a class flip of a slot) and the adoption reconcile never
// touch a PendingSlot entry: its class is its own.
func TestRewriteClassSkipsPendingSlot(t *testing.T) {
	adoptedStrict := bindingValue{Slot: PendingSlot, Flags: bindingStrict | bindingSubtree | bindingRingChecked}
	adoptedAudit := bindingValue{Slot: PendingSlot, Flags: bindingSubtree}
	f := newPublishFixtureWith(t, func(f *publishFixture) {
		f.state.data[uint32(1)] = slotState(0, 4)
		f.strictAt[Storage(1, 0)] = true
		f.members.data[uint64(98)] = adoptedAudit
		f.members.data[uint64(99)] = adoptedStrict
	})
	// The adoption reconcile left both as they were. This holds without
	// adopt's PendingSlot guard too (no slot record exists for PendingSlot),
	// so it does not prove the guard; it pins the outcome.
	if f.members.data[uint64(98)] != adoptedAudit || f.members.data[uint64(99)] != adoptedStrict ||
		f.b.adopted[98] != adoptedAudit || f.b.adopted[99] != adoptedStrict {
		t.Fatalf("adoption must keep pending entries: kernel %v adopted %v", f.members.data, f.b.adopted)
	}
	if err := f.b.Bind(pendingMark(true)); err != nil {
		t.Fatal(err)
	}
	other := ContainerIdentity{Runtime: "docker", ID: "d1", CgroupID: 43, CgroupPath: "/system.slice/docker-d1.scope"}
	if err := f.b.Bind(Binding{Container: other, Slot: 1}); err != nil {
		t.Fatal(err)
	}
	pending := f.members.data[parentIdentity.CgroupID]
	for _, step := range []struct {
		generation uint64
		strict     bool
	}{{5, false}, {6, true}, {7, false}} {
		f.clock = f.clock.Add(DefaultQuarantine)
		if err := f.b.Publish(f.publication(1, step.generation, step.strict)); err != nil {
			t.Fatal(err)
		}
		if v := f.members.data[other.CgroupID].(bindingValue); (v.Flags&bindingStrict != 0) != step.strict {
			t.Fatalf("generation %d: the slot's binding follows the class: %+v", step.generation, v)
		}
		if f.members.data[parentIdentity.CgroupID] != pending || f.members.data[uint64(98)] != adoptedAudit || f.members.data[uint64(99)] != adoptedStrict {
			t.Fatalf("generation %d: a flip touched a pending entry: %v", step.generation, f.members.data)
		}
	}
	// Called with PendingSlot itself, it writes nothing.
	before := puts(*f.members.log)
	f.b.mu.Lock()
	err := f.b.rewriteClass(PendingSlot, false)
	f.b.mu.Unlock()
	if err != nil || puts(*f.members.log) != before {
		t.Fatalf("rewriteClass(PendingSlot): %v, %d writes", err, puts(*f.members.log)-before)
	}
}

// HealNode refuses while a Strict adopted entry has no bind: for a PendingSlot
// entry the class is its own flag, not the configured class of the slot (the
// fixture's StrictSlot says Audit for every slot).
func TestHealNodeAdoptedPendingSlot(t *testing.T) {
	tests := []struct {
		name    string
		adopted bindingValue
		wantErr bool
	}{
		{name: "Strict pending", adopted: bindingValue{Slot: PendingSlot, Flags: bindingStrict | bindingSubtree}, wantErr: true},
		{name: "Audit pending", adopted: bindingValue{Slot: PendingSlot, Flags: bindingSubtree}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPublishFixtureWith(t, func(f *publishFixture) {
				f.members.data[parentIdentity.CgroupID] = tt.adopted
			})
			f.b.armed = &fakeMap{typ: ebpf.TaskStorage}
			f.b.witness = fakeWitness{0: 2}
			err := f.b.HealNode()
			if tt.wantErr {
				if err == nil || errors.Is(err, ErrNotHealable) || f.b.nodeFaultBase != 0 {
					t.Fatalf("a Strict pending adopted entry must keep the node faults: %v (base %d)", err, f.b.nodeFaultBase)
				}
				return
			}
			if err != nil || f.b.nodeFaultBase != 2 {
				t.Fatalf("an Audit pending adopted entry does not block the heal: %v (base %d)", err, f.b.nodeFaultBase)
			}
		})
	}
}

// A Strict pending binding that does not arm keeps the node faults counted:
// HealNode takes its class from the binding.
func TestHealNodeActivePendingSlotNotArmable(t *testing.T) {
	f := newPublishFixture(t)
	f.b.armed = &fakeMap{typ: ebpf.TaskStorage}
	f.b.witness = fakeWitness{0: 2}
	mark := pendingMark(true)
	mark.SkipArming = true
	if err := f.b.Bind(mark); err != nil {
		t.Fatal(err)
	}
	if err := f.b.HealNode(); !errors.Is(err, ErrNotHealable) {
		t.Fatalf("a Strict pending binding that does not arm: %v", err)
	}
}

// Kept reports the class of the entry the kernel holds for the cgroup.
func TestKeptPendingSlot(t *testing.T) {
	tests := []struct {
		name       string
		bind       *Binding
		adopted    *bindingValue
		wantStrict bool
	}{
		{name: "active Strict pending", bind: &Binding{Container: parentIdentity, Slot: PendingSlot, Strict: true, Subtree: true}, wantStrict: true},
		{name: "active Audit pending", bind: &Binding{Container: parentIdentity, Slot: PendingSlot, Subtree: true}},
		{name: "adopted Strict pending", adopted: &bindingValue{Slot: PendingSlot, Flags: bindingStrict}, wantStrict: true},
		{name: "adopted Audit pending", adopted: &bindingValue{Slot: PendingSlot}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPublishFixtureWith(t, func(f *publishFixture) {
				if tt.adopted != nil {
					f.members.data[parentIdentity.CgroupID] = *tt.adopted
				}
			})
			if tt.bind != nil {
				if err := f.b.Bind(*tt.bind); err != nil {
					t.Fatal(err)
				}
			}
			if kept, strict := f.b.Kept(parentIdentity.CgroupID); !kept || strict != tt.wantStrict {
				t.Fatalf("Kept: %v %v, want true %v", kept, strict, tt.wantStrict)
			}
		})
	}
}

// Rebind hands a parent cgroup over to the container that runs in it: one
// identity swap and one map write; the old identity no longer owns it.
func TestRebind(t *testing.T) {
	setup := func(t *testing.T) *publishFixture {
		f := newPublishFixture(t)
		if err := f.b.Publish(f.publication(1, 10, true)); err != nil {
			t.Fatal(err)
		}
		if err := f.b.Bind(pendingMark(true)); err != nil {
			t.Fatal(err)
		}
		return f
	}
	t.Run("hand-over", func(t *testing.T) {
		f := setup(t)
		before := puts(*f.members.log)
		if err := f.b.Rebind(parentIdentity, Binding{Container: containerInParent, Slot: 1}); err != nil {
			t.Fatal(err)
		}
		if n := puts(*f.members.log) - before; n != 1 {
			t.Fatalf("a rebind is one map write, got %d", n)
		}
		if v := f.members.data[parentIdentity.CgroupID].(bindingValue); v != (bindingValue{Slot: 1, Flags: bindingStrict}) {
			t.Fatalf("rebound entry %+v", v)
		}
		if c := f.b.active[parentIdentity.CgroupID]; c.Container != containerInParent {
			t.Fatalf("active identity %+v", c.Container)
		}
		// The old identity no longer owns the cgroup: its removal is stale.
		if err := f.b.Unbind(parentIdentity); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.members.data[parentIdentity.CgroupID]; !ok {
			t.Fatal("an unbind of the old identity must not remove the new binding")
		}
		if err := f.b.Unbind(containerInParent); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.members.data[parentIdentity.CgroupID]; ok {
			t.Fatal("an unbind of the new identity removes it")
		}
	})
	// An identity-only hand-over (the same kernel value): no write, and the
	// active binding is next itself, with its own SkipArming.
	t.Run("pending to pending, same value", func(t *testing.T) {
		f := setup(t)
		next := pendingMark(true)
		next.Container, next.SkipArming = containerInParent, true
		before := puts(*f.members.log)
		if err := f.b.Rebind(parentIdentity, next); err != nil {
			t.Fatal(err)
		}
		if n := puts(*f.members.log) - before; n != 0 {
			t.Fatalf("an unchanged kernel value needs no write, got %d", n)
		}
		if c := f.b.active[parentIdentity.CgroupID]; c != next {
			t.Fatalf("active binding %+v, want %+v", c, next)
		}
	})
	refusals := []struct {
		name string
		old  ContainerIdentity
		next Binding
		prep func(*publishFixture)
		want string
	}{
		{name: "old identity not bound", old: ContainerIdentity{Runtime: "parent", ID: "uid-2", CgroupID: 42, CgroupPath: parentIdentity.CgroupPath},
			next: Binding{Container: containerInParent, Slot: 1}, want: "no active binding of the old identity"},
		{name: "another cgroup", old: parentIdentity,
			next: Binding{Container: ContainerIdentity{Runtime: "containerd", ID: "c1", CgroupID: 43, CgroupPath: "/workloads.slice/other"}, Slot: 1}, want: "same cgroup"},
		{name: "same cgroup ID, another path", old: parentIdentity,
			next: Binding{Container: ContainerIdentity{Runtime: "containerd", ID: "c1", CgroupID: 42, CgroupPath: "/workloads.slice/moved"}, Slot: 1}, want: "same cgroup"},
		{name: "Strict on a real slot", old: parentIdentity, next: Binding{Container: containerInParent, Slot: 1, Strict: true}, want: "only a pending binding"},
		{name: "unpublished slot", old: parentIdentity, next: Binding{Container: containerInParent, Slot: 3}, want: "not published"},
		{name: "new identity bound elsewhere", old: parentIdentity, next: Binding{Container: containerInParent, Slot: 1},
			prep: func(f *publishFixture) {
				elsewhere := containerInParent
				elsewhere.CgroupID, elsewhere.CgroupPath = 44, "/workloads.slice/elsewhere"
				if err := f.b.Bind(Binding{Container: elsewhere, Slot: 1}); err != nil {
					t.Fatal(err)
				}
			}, want: "already bound to a different cgroup"},
		{name: "failed arming undoes the move", old: parentIdentity, next: Binding{Container: containerInParent, Slot: 1},
			prep: func(f *publishFixture) {
				f.b.armed = &fakeMap{typ: ebpf.TaskStorage}
				f.b.armExisting = func(Map, string) error { return errors.New("arming failed") }
			}, want: "arming failed"},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			f := setup(t)
			if tt.prep != nil {
				tt.prep(f)
			}
			mark := f.members.data[parentIdentity.CgroupID]
			err := f.b.Rebind(tt.old, tt.next)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Rebind: %v, want %q", err, tt.want)
			}
			// The parent cgroup keeps its mark and its identity.
			if got := f.members.data[parentIdentity.CgroupID]; got != mark {
				t.Fatalf("the pending mark must stay: %+v, want %+v", got, mark)
			}
			if c := f.b.active[parentIdentity.CgroupID]; c != pendingMark(true) {
				t.Fatalf("the old identity must keep the binding: %+v", c)
			}
			if err := f.b.Unbind(parentIdentity); err != nil {
				t.Fatal(err)
			}
			if _, ok := f.members.data[parentIdentity.CgroupID]; ok {
				t.Fatal("the old identity still removes its mark")
			}
		})
	}
}

// The per-slot counters never read PendingSlot: unknown, never zero.
func TestPendingSlotHasNoCounters(t *testing.T) {
	f := newPublishFixture(t)
	if _, err := f.b.SlotFaults(PendingSlot); err == nil {
		t.Fatal("SlotFaults(PendingSlot) must be an error, not zero faults")
	}
	f.b.attempts, f.b.unevaluated = fakeFaults{}, fakeFaults{}
	if _, err := f.b.Counters(PendingSlot); err == nil {
		t.Fatal("Counters(PendingSlot) must be an error, not zero counts")
	}
}
