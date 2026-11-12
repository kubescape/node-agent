// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// publishFixture is a long-lived instance with a slot state map and one
// policy map. Each publication writes key storage -> value generation.
type publishFixture struct {
	b       *Bindings
	state   *fakeMap
	policy  *fakeMap
	members *fakeMap
	faults  fakeFaults
	clock   time.Time
	// strictAt is the class ClassOf reads at a storage index.
	strictAt map[uint32]bool
}

func newPublishFixture(t *testing.T) *publishFixture {
	t.Helper()
	return newPublishFixtureWith(t, nil)
}

// newPublishFixtureWith starts the controller after setup has filled the
// fixture's maps (a pinned state to adopt).
func newPublishFixtureWith(t *testing.T, setup func(*publishFixture)) *publishFixture {
	t.Helper()
	log := &[]string{}
	f := &publishFixture{
		state:    &fakeMap{typ: ebpf.Array, key: 4, value: 8, max: MaxSlots, flag: unix.BPF_F_RDONLY_PROG, data: map[interface{}]interface{}{}, log: log, name: "state"},
		policy:   &fakeMap{typ: ebpf.Hash, data: map[interface{}]interface{}{}, log: log, name: "policy"},
		members:  &fakeMap{typ: ebpf.Hash, key: 8, value: 8, max: MaxBindings, data: map[interface{}]interface{}{}, log: log, name: "bindings"},
		faults:   fakeFaults{},
		clock:    time.Unix(1000, 0),
		strictAt: map[uint32]bool{},
	}
	b, err := New(Config{Name: "test", Generation: 1, Slots: 4, PublishMaps: []string{"policy"}, FaultMap: "f", StrictSlot: func(uint32) bool { return false }, SubtreeLevels: SubtreeLevels,
		Purge: func(m map[string]Map, storage uint32) error {
			if err := m["policy"].Delete(storage); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return err
			}
			return nil
		},
		ClassOf: func(m map[string]Map, storage uint32) (bool, error) { return f.strictAt[storage], nil },
		Occupied: func(m map[string]Map) (map[uint32]bool, error) {
			out := map[uint32]bool{}
			for k := range f.policy.data {
				out[k.(uint32)] = true
			}
			return out, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	b.listBindings = func(Map) (map[uint64]bindingValue, error) {
		out := map[uint64]bindingValue{}
		for k, v := range f.members.data {
			out[k.(uint64)] = v.(bindingValue)
		}
		return out, nil
	}
	b.now = func() time.Time { return f.clock }
	b.armExisting = func(Map, string) error { return nil }
	if setup != nil {
		setup(f)
	}
	if err := b.setPublishMaps(f.state, map[string]Map{"policy": f.policy}); err != nil {
		t.Fatal(err)
	}
	if err := b.start(nil, f.members, nil, f.faults, nil); err != nil {
		t.Fatal(err)
	}
	f.b = b
	return f
}

func (f *publishFixture) publication(slot uint32, generation uint64, strict bool) Publication {
	return Publication{Slot: slot, Generation: generation, Strict: strict,
		Write:  func(m map[string]Map, storage uint32) error { return m["policy"].Put(storage, generation) },
		Delete: func(m map[string]Map, storage uint32) error { return m["policy"].Delete(storage) }}
}

func (f *publishFixture) slotState(slot uint32) SlotState {
	s, _ := f.state.data[slot].(SlotState)
	return s
}

func TestPublishFlipsBuffersAndRetiresAfterQuarantine(t *testing.T) {
	f := newPublishFixture(t)
	if err := f.b.Publish(f.publication(1, 10, false)); err != nil {
		t.Fatal(err)
	}
	if s := f.slotState(1); s.Active() != 0 || s.Generation() != 10 || f.policy.data[uint32(2)] != uint64(10) {
		t.Fatalf("first publish: state %+v policy %v", s, f.policy.data)
	}
	if err := f.b.Publish(f.publication(1, 11, false)); err != nil {
		t.Fatal(err)
	}
	if s := f.slotState(1); s.Active() != 1 || s.Generation() != 11 || f.policy.data[uint32(3)] != uint64(11) {
		t.Fatalf("second publish: state %+v policy %v", s, f.policy.data)
	}
	if _, ok := f.policy.data[uint32(2)]; !ok {
		t.Fatal("the old buffer must stay during the quarantine")
	}
	// The old buffer is the next inactive one: busy until it is deleted.
	if err := f.b.Publish(f.publication(1, 12, false)); !errors.Is(err, ErrSlotBusy) {
		t.Fatalf("publish into a buffer in quarantine: %v", err)
	}
	f.clock = f.clock.Add(DefaultQuarantine)
	if err := f.b.Collect(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.policy.data[uint32(2)]; ok {
		t.Fatal("the old buffer must be deleted after the quarantine")
	}
	if f.b.SlotGeneration(1) != 11 {
		t.Fatalf("generation %d", f.b.SlotGeneration(1))
	}
}

func TestFailedPublishKeepsLastGood(t *testing.T) {
	f := newPublishFixture(t)
	if err := f.b.Publish(f.publication(0, 10, true)); err != nil {
		t.Fatal(err)
	}
	bad := f.publication(0, 11, true)
	bad.Write = func(m map[string]Map, storage uint32) error {
		_ = m["policy"].Put(storage, uint64(11)) // half written
		return fmt.Errorf("capacity")
	}
	if err := f.b.Publish(bad); err == nil {
		t.Fatal("a failed write must fail the publish")
	}
	if s := f.slotState(0); s.Active() != 0 || s.Generation() != 10 {
		t.Fatalf("the slot must keep its last-good publication: %+v", s)
	}
	if _, ok := f.policy.data[uint32(1)]; ok {
		t.Fatal("the half-written buffer must be deleted")
	}
	f.state.putErr = fmt.Errorf("map full")
	if err := f.b.Publish(f.publication(0, 12, true)); err == nil {
		t.Fatal("a failed flip must fail the publish")
	}
	f.state.putErr = nil
	if _, ok := f.policy.data[uint32(1)]; ok || f.b.SlotGeneration(0) != 10 {
		t.Fatal("a failed flip must delete the new buffer and keep the generation")
	}
}

func TestBindNeedsPublishedSlotAndTakesItsClass(t *testing.T) {
	f := newPublishFixture(t)
	if err := f.b.Bind(Binding{Container: identity, Slot: 2}); err == nil {
		t.Fatal("a bind to an unpublished slot must fail")
	}
	if err := f.b.Publish(f.publication(2, 10, true)); err != nil {
		t.Fatal(err)
	}
	if err := f.b.Bind(Binding{Container: identity, Slot: 2}); err != nil {
		t.Fatal(err)
	}
	if v := f.members.data[identity.CgroupID].(bindingValue); v.Flags&bindingStrict == 0 {
		t.Fatalf("a Strict publication makes Strict bindings: %+v", v)
	}
	// Strict to Audit in place: the binding follows the class.
	f.clock = f.clock.Add(DefaultQuarantine)
	if err := f.b.Publish(f.publication(2, 11, false)); err != nil {
		t.Fatal(err)
	}
	if v := f.members.data[identity.CgroupID].(bindingValue); v.Flags&bindingStrict != 0 {
		t.Fatalf("an Audit publication makes Audit bindings: %+v", v)
	}
	f.clock = f.clock.Add(DefaultQuarantine)
	if err := f.b.Publish(f.publication(2, 12, true)); err != nil {
		t.Fatal(err)
	}
	if v := f.members.data[identity.CgroupID].(bindingValue); v.Flags&bindingStrict == 0 {
		t.Fatalf("back to Strict: %+v", v)
	}
}

func TestFreeQuarantinesTheSlot(t *testing.T) {
	f := newPublishFixture(t)
	if err := f.b.Publish(f.publication(3, 10, false)); err != nil {
		t.Fatal(err)
	}
	if err := f.b.Bind(Binding{Container: identity, Slot: 3}); err != nil {
		t.Fatal(err)
	}
	if err := f.b.Free(3); err == nil {
		t.Fatal("a bound slot must not be freed")
	}
	if err := f.b.Unbind(identity); err != nil {
		t.Fatal(err)
	}
	if err := f.b.Free(3); err != nil {
		t.Fatal(err)
	}
	if s := f.slotState(3); s.Generation() != 0 {
		t.Fatalf("a freed slot has no generation: %+v", s)
	}
	if f.b.Available(3) {
		t.Fatal("a freed slot is not reused during the quarantine")
	}
	if err := f.b.Publish(f.publication(3, 11, false)); !errors.Is(err, ErrSlotBusy) {
		t.Fatalf("publish into a slot in quarantine: %v", err)
	}
	f.clock = f.clock.Add(DefaultQuarantine)
	if !f.b.Available(3) {
		t.Fatal("the slot is free after the quarantine")
	}
	if err := f.b.Publish(f.publication(3, 11, false)); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.policy.data[uint32(6)]; !ok {
		t.Fatal("the reused slot writes buffer 0 again")
	}
}

func TestReusedSlotStartsWithNoFaultsAndHeal(t *testing.T) {
	f := newPublishFixture(t)
	f.faults[1] = 4 // left by an earlier use of the slot
	if err := f.b.Publish(f.publication(1, 10, true)); err != nil {
		t.Fatal(err)
	}
	if n, err := f.b.SlotFaults(1); err != nil || n != 0 {
		t.Fatalf("a new publication starts with no fault: %d %v", n, err)
	}
	f.faults[1] = 6
	if n, _ := f.b.SlotFaults(1); n != 2 {
		t.Fatalf("faults after the publication: %d", n)
	}
	var armed []string
	f.b.armExisting = func(_ Map, path string) error { armed = append(armed, path); return nil }
	f.b.armed = &fakeMap{typ: ebpf.TaskStorage}
	if err := f.b.Bind(Binding{Container: identity, Slot: 1}); err != nil {
		t.Fatal(err)
	}
	armed = nil
	if err := f.b.Heal(1); err != nil {
		t.Fatal(err)
	}
	if len(armed) != 1 {
		t.Fatalf("heal arms the bound cgroups again: %v", armed)
	}
	if n, _ := f.b.SlotFaults(1); n != 0 {
		t.Fatalf("faults after heal: %d", n)
	}
}

func TestPublishRequiresLayoutAndMode(t *testing.T) {
	if _, err := New(Config{Name: "x", Generation: 1, Slots: MaxSlots + 1, PublishMaps: []string{"p"}}); err == nil {
		t.Fatal("too many slots")
	}
	if _, err := New(Config{Name: "x", Generation: 1, Slots: 1}); err == nil {
		t.Fatal("neither a writer nor publish maps")
	}
	if _, err := New(Config{Name: "x", Generation: 1, Slots: 1, PublishMaps: []string{"p"}}); err == nil {
		t.Fatal("publish maps without Purge and ClassOf")
	}
	b, err := New(Config{Name: "x", Generation: 1, Slots: 1, PublishMaps: []string{"p"},
		Purge: func(map[string]Map, uint32) error { return nil }, ClassOf: func(map[string]Map, uint32) (bool, error) { return false, nil },
		Occupied: func(map[string]Map) (map[uint32]bool, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	writable := &fakeMap{typ: ebpf.Array, key: 4, value: 8, max: MaxSlots, data: map[interface{}]interface{}{}, log: &[]string{}}
	if err := b.setPublishMaps(writable, nil); err == nil {
		t.Fatal("the slot state must be read-only for programs")
	}
	frozen, _ := New(Config{Name: "y", Generation: 1, Slots: 1, PolicyMap: "p", WritePolicy: func(Map) error { return nil }})
	if err := frozen.Publish(Publication{}); err == nil {
		t.Fatal("a frozen instance does not publish")
	}
}

func TestHealNodeRestartsNodeFaults(t *testing.T) {
	f := newPublishFixture(t)
	w := fakeWitness{0: 3}
	f.b.witness = w
	if got, err := f.b.ArmingWitness(); err != nil || got.NodeFaults != 3 {
		t.Fatalf("witness: %+v %v", got, err)
	}
	if err := f.b.Publish(f.publication(0, 10, true)); err != nil {
		t.Fatal(err)
	}
	if err := f.b.Bind(Binding{Container: identity, Slot: 0}); err != nil {
		t.Fatal(err)
	}
	var armed []string
	f.b.armed = &fakeMap{typ: ebpf.TaskStorage}
	f.b.armExisting = func(_ Map, path string) error { armed = append(armed, path); return nil }
	if err := f.b.HealNode(); err != nil || len(armed) != 1 {
		t.Fatalf("heal: %v %v", err, armed)
	}
	if got, _ := f.b.ArmingWitness(); got.NodeFaults != 0 {
		t.Fatalf("node faults after heal: %+v", got)
	}
	w[0] = 5
	if got, _ := f.b.ArmingWitness(); got.NodeFaults != 2 {
		t.Fatalf("node faults after a new fault: %+v", got)
	}
	if !f.b.Strict(0) || f.b.Strict(1) {
		t.Fatal("Strict follows the publication")
	}
}

func TestFailedCleanupKeepsTheBufferBusy(t *testing.T) {
	f := newPublishFixture(t)
	if err := f.b.Publish(f.publication(0, 10, true)); err != nil {
		t.Fatal(err)
	}
	bad := f.publication(0, 11, true)
	bad.Write = func(m map[string]Map, storage uint32) error {
		_ = m["policy"].Put(storage, uint64(11))
		return fmt.Errorf("capacity")
	}
	failDelete := true
	bad.Delete = func(m map[string]Map, storage uint32) error {
		if failDelete {
			return fmt.Errorf("busy")
		}
		return m["policy"].Delete(storage)
	}
	if err := f.b.Publish(bad); err == nil {
		t.Fatal("the failed publish must fail")
	}
	// The leftover entries are not overwritten by the next publication.
	if err := f.b.Publish(f.publication(0, 12, true)); !errors.Is(err, ErrSlotBusy) {
		t.Fatalf("a buffer whose cleanup failed must stay busy: %v", err)
	}
	failDelete = false
	if err := f.b.Collect(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.policy.data[uint32(1)]; ok {
		t.Fatal("collect must delete the leftover buffer")
	}
	if err := f.b.Publish(f.publication(0, 12, true)); err != nil {
		t.Fatal(err)
	}
}

func TestFailedAuditRewriteIsRetried(t *testing.T) {
	f := newPublishFixture(t)
	if err := f.b.Publish(f.publication(2, 10, true)); err != nil {
		t.Fatal(err)
	}
	if err := f.b.Bind(Binding{Container: identity, Slot: 2}); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(DefaultQuarantine)
	f.members.putErr = fmt.Errorf("map busy")
	if err := f.b.Publish(f.publication(2, 11, false)); err == nil {
		t.Fatal("the failed rewrite must be reported")
	}
	if v := f.members.data[identity.CgroupID].(bindingValue); v.Flags&bindingStrict == 0 {
		t.Fatal("the fake must still hold the Strict class")
	}
	f.members.putErr = nil
	if err := f.b.Collect(); err != nil {
		t.Fatal(err)
	}
	if v := f.members.data[identity.CgroupID].(bindingValue); v.Flags&bindingStrict != 0 {
		t.Fatalf("collect must retry the rewrite to Audit: %+v", v)
	}
}

func TestHealNeedsArming(t *testing.T) {
	f := newPublishFixture(t)
	if err := f.b.Publish(f.publication(1, 10, true)); err != nil {
		t.Fatal(err)
	}
	f.faults[1] = 3
	if err := f.b.Heal(1); err == nil {
		t.Fatal("a heal with no arming map must fail")
	}
	if n, _ := f.b.SlotFaults(1); n != 3 {
		t.Fatalf("faults must stay counted: %d", n)
	}
}

// A new instance adopts the pinned state: the published slots with their
// class, the kernel bindings, and purges what a crash left in a buffer that is
// not active.
func TestAdoptPinnedState(t *testing.T) {
	f := newPublishFixtureWith(t, func(f *publishFixture) {
		f.state.data[uint32(2)] = slotState(1, 7) // slot 2: buffer 1 active
		f.policy.data[uint32(5)] = uint64(7)      // its publication
		f.policy.data[uint32(4)] = uint64(6)      // a half-written leftover
		f.policy.data[uint32(0)] = uint64(3)      // a buffer of an unpublished slot
		f.strictAt[5] = true
		f.members.data[uint64(99)] = bindingValue{Slot: 2, Flags: bindingStrict}
	})
	if got := f.b.PublishedSlots(); len(got) != 1 || got[2] != 7 {
		t.Fatalf("published slots %v", got)
	}
	if _, ok := f.policy.data[uint32(5)]; !ok {
		t.Fatal("the active buffer must stay")
	}
	// The other buffers go after a quarantine, like a replaced buffer.
	if _, ok := f.policy.data[uint32(4)]; !ok || f.b.Available(0) {
		t.Fatal("a non-active buffer waits its quarantine; its slot is not free yet")
	}
	f.clock = f.clock.Add(DefaultQuarantine)
	if err := f.b.Collect(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.policy.data[uint32(4)]; ok {
		t.Fatal("the inactive buffer must be purged")
	}
	if _, ok := f.policy.data[uint32(0)]; ok || !f.b.Available(0) {
		t.Fatal("an unpublished slot's buffers must be purged")
	}
	if !f.b.Strict(2) {
		t.Fatal("the adopted class comes from the active publication")
	}
	if got := f.b.AdoptedBindings(); got[2] != 1 {
		t.Fatalf("adopted bindings %v", got)
	}
	if err := f.b.Free(2); err == nil {
		t.Fatal("a slot with adopted bindings must not be freed")
	}
	// A publication into an adopted slot writes its inactive buffer.
	if err := f.b.Publish(f.publication(2, 8, true)); err != nil {
		t.Fatal(err)
	}
	if s := f.slotState(2); s.Active() != 0 || s.Generation() != 8 {
		t.Fatalf("publication into an adopted slot: %+v", s)
	}
	// Keep the Strict adopted bindings, then drop them.
	if n, err := f.b.DropAdopted(func(slot uint32, strict bool) bool { return strict }); err != nil || n != 1 {
		t.Fatalf("keep Strict: %d %v", n, err)
	}
	if n, err := f.b.DropAdopted(nil); err != nil || n != 0 {
		t.Fatalf("drop: %d %v", n, err)
	}
	if _, ok := f.members.data[uint64(99)]; ok {
		t.Fatal("the adopted kernel binding must be deleted")
	}
	if err := f.b.Free(2); err != nil {
		t.Fatal(err)
	}
}

// A bind takes over an adopted kernel binding of the same cgroup.
func TestBindTakesOverAdoptedBinding(t *testing.T) {
	f := newPublishFixtureWith(t, func(f *publishFixture) {
		f.state.data[uint32(1)] = slotState(0, 4)
		f.members.data[identity.CgroupID] = bindingValue{Slot: 1}
	})
	if err := f.b.Bind(Binding{Container: identity, Slot: 1}); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.b.DropAdopted(nil); n != 0 {
		t.Fatal("a bound cgroup is no longer adopted")
	}
	if _, ok := f.members.data[identity.CgroupID]; !ok {
		t.Fatal("the bound cgroup's entry must stay")
	}
}

// A bind whose arming fails keeps the adopted entry, so the container stays
// protected until a retry binds it. An unbind removes an adopted entry.
func TestFailedBindKeepsAdoptedBinding(t *testing.T) {
	f := newPublishFixtureWith(t, func(f *publishFixture) {
		f.state.data[uint32(1)] = slotState(0, 4)
		f.state.data[uint32(2)] = slotState(0, 5)
		f.members.data[identity.CgroupID] = bindingValue{Slot: 1}
	})
	f.b.armed = &fakeMap{typ: ebpf.TaskStorage}
	f.b.armExisting = func(Map, string) error { return errors.New("walk failed") }
	if err := f.b.Bind(Binding{Container: identity, Slot: 2}); err == nil {
		t.Fatal("the bind must fail")
	}
	if v, ok := f.members.data[identity.CgroupID].(bindingValue); !ok || v.Slot != 1 {
		t.Fatalf("the adopted entry must stay: %+v", f.members.data)
	}
	if got := f.b.AdoptedBindings(); got[1] != 1 {
		t.Fatalf("adopted %v", got)
	}
	if err := f.b.Unbind(identity); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.members.data[identity.CgroupID]; ok || len(f.b.AdoptedBindings()) != 0 {
		t.Fatal("an unbind must remove the adopted entry")
	}
}

// An adopted binding takes the class of its slot (a crash in the middle of a
// class rewrite can leave it stale).
func TestAdoptReconcilesBindingClass(t *testing.T) {
	f := newPublishFixtureWith(t, func(f *publishFixture) {
		f.state.data[uint32(1)] = slotState(0, 4) // an Audit publication
		f.policy.data[uint32(2)] = uint64(4)
		f.members.data[uint64(77)] = bindingValue{Slot: 1, Flags: bindingStrict}
	})
	if v := f.members.data[uint64(77)].(bindingValue); v.Flags&bindingStrict != 0 {
		t.Fatalf("a Strict flag on an Audit slot must be cleared: %+v", v)
	}
	if got := f.b.AdoptedBindings(); got[1] != 1 {
		t.Fatalf("adopted %v", got)
	}
}

// ResetFaults counts the faults from now on, for the slots and the node.
func TestResetFaults(t *testing.T) {
	f := newPublishFixture(t)
	if err := f.b.Publish(f.publication(0, 10, true)); err != nil {
		t.Fatal(err)
	}
	f.faults[0] = 3
	w := fakeWitness{0: 2}
	f.b.witness = w
	if n, _ := f.b.SlotFaults(0); n != 3 {
		t.Fatalf("faults %d", n)
	}
	if err := f.b.ResetFaults(); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.b.SlotFaults(0); n != 0 {
		t.Fatalf("faults after reset %d", n)
	}
	if got, _ := f.b.ArmingWitness(); got.NodeFaults != 0 {
		t.Fatalf("node faults after reset %+v", got)
	}
}
