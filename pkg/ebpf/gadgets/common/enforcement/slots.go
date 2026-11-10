// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Long-lived instance: a slot's policy is published in place (../slots.h).
// Each slot has two storage buffers; the section's policy maps are keyed by
// the storage index. Publish writes the inactive buffer, flips the slot state
// in one map write and deletes the old buffer after a quarantine. A failed
// publish leaves the active buffer, so the slot keeps its last-good policy.

const (
	// MaxSlots matches SANDBOX_SLOTS in ../slots.h.
	MaxSlots = 64
	// SlotStateMap is the slot state array of ../slots.h, after
	// Config.MapPrefix.
	SlotStateMap = "slot_state"
	// DefaultQuarantine is how long a replaced or freed buffer stays. The
	// hooks are short and read the slot state once per call; this is a time
	// bound, checked by the kernel race test, not an RCU proof.
	DefaultQuarantine = 2 * time.Second
)

// ErrSlotBusy: the slot, or its inactive buffer, is still in quarantine.
var ErrSlotBusy = errors.New("policy slot in quarantine")

// ErrNotHealable: a heal cannot arm every task it would confirm (no arming
// map, or a binding that never arms). The faults stay counted.
var ErrNotHealable = errors.New("faults cannot heal in place")

// SlotState matches struct slot_state in ../slots.h: generation << 1 |
// active buffer, one 8-byte value that a hook reads with one load.
type SlotState struct {
	State uint64
}

func slotState(active uint32, generation uint64) SlotState {
	return SlotState{State: generation<<1 | uint64(active&1)}
}

// Active and Generation decode a slot state.
func (s SlotState) Active() uint32     { return uint32(s.State & 1) }
func (s SlotState) Generation() uint64 { return s.State >> 1 }

// Storage is the storage index of a slot's buffer (../slots.h).
func Storage(slot, buffer uint32) uint32 { return slot*2 + buffer }

// Publication is one compiled policy of one slot.
type Publication struct {
	Slot uint32
	// Generation identifies the publication's policy (nonzero; under 2^63).
	// Verdicts carry it. The slots of one instance start share one.
	Generation uint64
	// Strict: the policy enforces. A binding of the slot gets
	// BINDING_STRICT, so the program fails closed on a fault.
	Strict bool
	// Write writes the entries keyed by storage, the slot header last. maps
	// holds Config.PublishMaps.
	Write func(maps map[string]Map, storage uint32) error
	// Delete removes the entries that Write wrote for storage. It runs on a
	// failed publish and after the quarantine of a replaced buffer.
	Delete func(maps map[string]Map, storage uint32) error
}

type slotRecord struct {
	active     uint32
	generation uint64
	strict     bool
	delete     func(map[string]Map, uint32) error
	// faultBase is the slot's fault count at its first publish (or last
	// heal): SlotFaults reports the faults after it.
	faultBase uint64
	// freedUntil: the slot was freed; it is reusable after this time.
	freedUntil time.Time
	published  bool
}

type retirement struct {
	storage uint32
	delete  func(map[string]Map, uint32) error
	after   time.Time
}

// setPublishMaps checks the slot state layout (called by Start).
func (b *Bindings) setPublishMaps(state Map, publish map[string]Map) error {
	if state == nil || state.Type() != ebpf.Array || state.KeySize() != 4 || state.ValueSize() != 8 ||
		state.MaxEntries() != MaxSlots || state.Flags()&unix.BPF_F_RDONLY_PROG == 0 {
		return fmt.Errorf("invalid slot state map layout")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.slotState, b.publish = state, publish
	return nil
}

// strict is the class of a slot: the published policy's, else the
// configured one (a frozen instance). Called with mu held.
func (b *Bindings) strict(slot uint32) bool {
	if r := b.slots[slot]; r != nil && r.published {
		return r.strict
	}
	return b.config.StrictSlot != nil && b.config.StrictSlot(slot)
}

// Publish writes p into the slot's inactive buffer and flips the slot to it.
// An error before the flip keeps the last-good policy. An error of the
// Strict-to-Audit binding rewrite after the flip leaves the new policy active;
// collect retries the rewrite.
func (b *Bindings) Publish(p Publication) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready || b.stopped || b.slotState == nil {
		return fmt.Errorf("binding controller is not publishing")
	}
	return b.publishSlot(p)
}

// publishSlot is Publish with mu held (also used at start).
func (b *Bindings) publishSlot(p Publication) error {
	if p.Slot >= b.config.Slots || p.Generation == 0 || p.Generation>>63 != 0 || p.Write == nil || p.Delete == nil {
		return fmt.Errorf("invalid publication for slot %d", p.Slot)
	}
	b.collect()
	r := b.slots[p.Slot]
	if r != nil && !r.published && b.now().Before(r.freedUntil) {
		return ErrSlotBusy
	}
	buffer := uint32(0)
	if r != nil && r.published {
		buffer = 1 - r.active
	}
	storage := Storage(p.Slot, buffer)
	for _, old := range b.retiring {
		if old.storage == storage {
			return ErrSlotBusy // the inactive buffer is not deleted yet
		}
	}
	if err := p.Write(b.publish, storage); err != nil {
		return errors.Join(fmt.Errorf("publishing slot %d: %w", p.Slot, err), b.discard(p, storage))
	}
	first := r == nil || !r.published
	if !first && r.strict != p.Strict && p.Strict {
		// Audit to Strict: the bindings claim Strict before the flip, so
		// during this window the old Audit policy fails closed on a fault.
		if err := b.rewriteClass(p.Slot, true); err != nil {
			return errors.Join(err, b.restoreClass(p.Slot, r.strict), b.discard(p, storage))
		}
	}
	if err := b.slotState.Put(p.Slot, slotState(buffer, p.Generation)); err != nil {
		err = fmt.Errorf("flipping slot %d: %w", p.Slot, err)
		if !first && r.strict != p.Strict {
			err = errors.Join(err, b.restoreClass(p.Slot, r.strict))
		}
		return errors.Join(err, b.discard(p, storage))
	}
	next := &slotRecord{active: buffer, generation: p.Generation, strict: p.Strict, delete: p.Delete, published: true}
	if first {
		// A new or reused slot starts with no fault.
		next.faultBase = b.faultCount(p.Slot)
	} else {
		next.faultBase = r.faultBase
		b.retiring = append(b.retiring, retirement{storage: Storage(p.Slot, r.active), delete: r.delete, after: b.now().Add(b.config.Quarantine)})
	}
	b.slots[p.Slot] = next
	if !first && r.strict && !p.Strict {
		// Strict to Audit: after the flip, so a binding never claims
		// Audit for a Strict policy. A failure is retried by collect, so
		// an Audit policy does not keep blocking on faults.
		if err := b.rewriteClass(p.Slot, false); err != nil {
			b.classRetry[p.Slot] = true
			return err
		}
	}
	return nil
}

// restoreClass rewrites the slot's bindings back to the active policy's class
// after a failed publish; a failure is retried by collect.
func (b *Bindings) restoreClass(slot uint32, strict bool) error {
	err := b.rewriteClass(slot, strict)
	if err != nil {
		b.classRetry[slot] = true
	}
	return err
}

// discard deletes a buffer that a failed publish wrote. When the delete fails
// too, the buffer stays busy (retired now): collect retries the delete, and no
// publication writes over leftover entries.
func (b *Bindings) discard(p Publication, storage uint32) error {
	err := p.Delete(b.publish, storage)
	if err != nil {
		b.retiring = append(b.retiring, retirement{storage: storage, delete: p.Delete, after: b.now()})
	}
	return err
}

// rewriteClass writes the bindings of slot with the class strict. Called
// with mu held, around a flip that changes the class.
func (b *Bindings) rewriteClass(slot uint32, strict bool) error {
	r := b.slots[slot]
	saved := r.strict
	r.strict = strict
	defer func() { r.strict = saved }()
	var errs []error
	for id, c := range b.active {
		if c.Slot == slot {
			if err := b.members.Put(id, b.value(c)); err != nil {
				errs = append(errs, fmt.Errorf("rewriting binding class: %w", err))
			}
		}
	}
	return errors.Join(errs...)
}

// Free retires a slot that no binding uses: its state is cleared, its buffer
// is deleted after the quarantine, and it is not reused before then.
func (b *Bindings) Free(slot uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.slotState == nil || !b.ready || b.stopped {
		return fmt.Errorf("binding controller is not publishing")
	}
	r := b.slots[slot]
	if r == nil || !r.published {
		return nil
	}
	for _, c := range b.active {
		if c.Slot == slot {
			return fmt.Errorf("slot %d is still bound", slot)
		}
	}
	for _, v := range b.adopted {
		if v.Slot == slot {
			return fmt.Errorf("slot %d still has adopted bindings", slot)
		}
	}
	if err := b.slotState.Put(slot, SlotState{}); err != nil {
		return fmt.Errorf("clearing slot %d: %w", slot, err)
	}
	until := b.now().Add(b.config.Quarantine)
	b.retiring = append(b.retiring, retirement{storage: Storage(slot, r.active), delete: r.delete, after: until})
	b.slots[slot] = &slotRecord{freedUntil: until}
	return nil
}

// Available reports whether a slot can take a new publication now: never
// published, or freed and out of quarantine.
func (b *Bindings) Available(slot uint32) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.slots[slot]
	return slot < b.config.Slots && (r == nil || (!r.published && !b.now().Before(r.freedUntil)))
}

// Collect deletes the buffers whose quarantine ended. Call it from the
// owner's reconcile; Publish calls it too.
func (b *Bindings) Collect() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.collect()
}

// collect is Collect with mu held. A failed delete is retried next time.
func (b *Bindings) collect() error {
	var kept []retirement
	var errs []error
	now := b.now()
	for _, r := range b.retiring {
		if now.Before(r.after) {
			kept = append(kept, r)
			continue
		}
		if err := r.delete(b.publish, r.storage); err != nil {
			kept = append(kept, r)
			errs = append(errs, fmt.Errorf("deleting storage %d: %w", r.storage, err))
		}
	}
	b.retiring = kept
	for slot := range b.classRetry {
		r := b.slots[slot]
		if r == nil || !r.published {
			delete(b.classRetry, slot)
			continue
		}
		if err := b.rewriteClass(slot, r.strict); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(b.classRetry, slot)
	}
	return errors.Join(errs...)
}

// SlotGeneration returns the generation of the slot's active publication, or
// 0.
func (b *Bindings) SlotGeneration(slot uint32) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r := b.slots[slot]; r != nil && r.published {
		return r.generation
	}
	return 0
}

// Heal arms the running tasks of every bound cgroup of the slot again, then
// counts the slot's faults from the count read before (a fault during the
// heal still counts). It is the long-lived instance's answer to lost marks:
// no reload.
func (b *Bindings) Heal(slot uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.slots[slot]
	if r == nil || !r.published || b.faults == nil {
		return fmt.Errorf("slot %d has no publication to heal", slot)
	}
	var count uint64
	if err := b.faults.Lookup(slot, &count); err != nil {
		return fmt.Errorf("reading tracking faults: %w", err)
	}
	if b.armed == nil {
		return fmt.Errorf("%w: no arming map (slot %d)", ErrNotHealable, slot)
	}
	skipped := false
	for _, c := range b.active {
		if c.Slot != slot {
			continue
		}
		if !armable(c) {
			skipped = true
			continue
		}
		if err := b.armExisting(b.armed, c.Container.CgroupPath); err != nil && !errors.Is(err, ErrContainerGone) {
			return err
		}
	}
	if skipped {
		// A binding that never arms covers tasks this heal did not mark:
		// the faults stay counted.
		return fmt.Errorf("%w: slot %d has bindings that do not arm", ErrNotHealable, slot)
	}
	r.faultBase = count
	return nil
}

// HealNode arms the running tasks of every bound cgroup again, then counts
// node faults from the count read before. A node fault (a lost child mark that
// may start in any cgroup) affects every Strict slot; this is the long-lived
// instance's answer to it: no reload.
func (b *Bindings) HealNode() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.witness == nil {
		return fmt.Errorf("no witness map configured")
	}
	var count uint64
	if err := b.witness.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("reading node faults: %w", err)
	}
	if b.armed == nil {
		return fmt.Errorf("%w: no arming map", ErrNotHealable)
	}
	skipped := false
	for _, c := range b.active {
		if !armable(c) {
			// Node faults concern Strict slots only.
			skipped = skipped || b.strict(c.Slot)
			continue
		}
		if err := b.armExisting(b.armed, c.Container.CgroupPath); err != nil && !errors.Is(err, ErrContainerGone) {
			return err
		}
	}
	if skipped {
		return fmt.Errorf("%w: Strict bindings that do not arm", ErrNotHealable)
	}
	b.nodeFaultBase = count
	return nil
}

// armable reports whether a heal can arm the tasks a binding covers.
func armable(Binding) bool { return true }

// Strict reports the class of a slot: its publication's, else the
// configured one.
func (b *Bindings) Strict(slot uint32) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.strict(slot)
}

// faultCount reads the slot's fault counter, 0 when unavailable. Called with
// mu held.
func (b *Bindings) faultCount(slot uint32) uint64 {
	var count uint64
	if b.faults != nil {
		_ = b.faults.Lookup(slot, &count)
	}
	return count
}

// adopt reads the pinned state that a previous instance of the section left
// (or that a running one holds, for a second instance): the published slots,
// with their class, and the kernel bindings. A buffer that is not active is
// purged: a crash can leave a publication half written there. Faults count
// from zero for an adopted slot, so a fault before the restart still counts
// until a heal. Called with mu held, before any publication.
func (b *Bindings) adopt() error {
	state, ok := b.slotState.(interface {
		Lookup(key, valueOut interface{}) error
	})
	if !ok {
		return fmt.Errorf("slot state map cannot be read")
	}
	var errs []error
	for slot := uint32(0); slot < b.config.Slots; slot++ {
		var s SlotState
		if err := state.Lookup(slot, &s); err != nil {
			return fmt.Errorf("reading slot %d state: %w", slot, err)
		}
		if s.Generation() == 0 {
			errs = append(errs, b.config.Purge(b.publish, Storage(slot, 0)), b.config.Purge(b.publish, Storage(slot, 1)))
			continue
		}
		strict, err := b.config.ClassOf(b.publish, Storage(slot, s.Active()))
		if err != nil {
			return fmt.Errorf("reading the class of slot %d: %w", slot, err)
		}
		b.slots[slot] = &slotRecord{active: s.Active(), generation: s.Generation(), strict: strict, delete: b.config.Purge, published: true}
		errs = append(errs, b.config.Purge(b.publish, Storage(slot, 1-s.Active())))
	}
	adopted, err := b.listBindings(b.members)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("reading the pinned bindings: %w", err))...)
	}
	b.adopted = adopted
	return errors.Join(errs...)
}

// listPinnedBindings returns the entries of the binding map.
func listPinnedBindings(m Map) (map[uint64]bindingValue, error) {
	em, ok := m.(*ebpf.Map)
	if !ok {
		return nil, fmt.Errorf("binding map cannot be listed")
	}
	out := map[uint64]bindingValue{}
	var (
		key   uint64
		value bindingValue
	)
	it := em.Iterate()
	for it.Next(&key, &value) {
		out[key] = value
	}
	return out, it.Err()
}

// PublishedSlots returns each published slot with its generation: the
// publications of this instance and the adopted ones.
func (b *Bindings) PublishedSlots() map[uint32]uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[uint32]uint64{}
	for slot, r := range b.slots {
		if r.published {
			out[slot] = r.generation
		}
	}
	return out
}

// AdoptedBindings returns the adopted kernel bindings that no Bind took over,
// per slot.
func (b *Bindings) AdoptedBindings() map[uint32]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[uint32]int{}
	for _, v := range b.adopted {
		out[v.Slot]++
	}
	return out
}

// DropAdopted deletes the adopted kernel bindings that no Bind took over,
// except those keep accepts (by slot and class). It returns how many remain.
func (b *Bindings) DropAdopted(keep func(slot uint32, strict bool) bool) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var errs []error
	for cgroup, v := range b.adopted {
		if keep != nil && keep(v.Slot, v.Flags&bindingStrict != 0) {
			continue
		}
		if err := b.members.Delete(cgroup); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("removing adopted binding: %w", err))
			continue
		}
		delete(b.adopted, cgroup)
	}
	return len(b.adopted), errors.Join(errs...)
}
