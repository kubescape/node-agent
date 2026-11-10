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
}

func newPublishFixture(t *testing.T) *publishFixture {
	t.Helper()
	log := &[]string{}
	f := &publishFixture{
		state:   &fakeMap{typ: ebpf.Array, key: 4, value: 8, max: MaxSlots, flag: unix.BPF_F_RDONLY_PROG, data: map[interface{}]interface{}{}, log: log, name: "state"},
		policy:  &fakeMap{typ: ebpf.Hash, data: map[interface{}]interface{}{}, log: log, name: "policy"},
		members: &fakeMap{typ: ebpf.Hash, key: 8, value: 8, max: MaxBindings, data: map[interface{}]interface{}{}, log: log, name: "bindings"},
		faults:  fakeFaults{},
		clock:   time.Unix(1000, 0),
	}
	b, err := New(Config{Name: "test", Generation: 1, Slots: 4, PublishMaps: []string{"policy"}, FaultMap: "f", StrictSlot: func(uint32) bool { return false }, SubtreeLevels: SubtreeLevels})
	if err != nil {
		t.Fatal(err)
	}
	b.now = func() time.Time { return f.clock }
	b.armExisting = func(Map, string) error { return nil }
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
	b, err := New(Config{Name: "x", Generation: 1, Slots: 1, PublishMaps: []string{"p"}})
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
