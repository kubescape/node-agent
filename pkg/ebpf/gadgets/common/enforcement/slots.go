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
	// SlotStateMap is the slot state array of ../slots.h.
	SlotStateMap = "sandbox_slot_state"
	// DefaultQuarantine is how long a replaced or freed buffer stays. The
	// hooks are short and read the slot state once per call; this is a time
	// bound, checked by the kernel race test, not an RCU proof.
	DefaultQuarantine = 2 * time.Second
)

// ErrSlotBusy: the slot, or its inactive buffer, is still in quarantine.
var ErrSlotBusy = errors.New("policy slot in quarantine")

// SlotState matches struct slot_state in ../slots.h.
type SlotState struct {
	Active     uint32
	_          uint32
	Generation uint64
}

// Storage is the storage index of a slot's buffer (../slots.h).
func Storage(slot, buffer uint32) uint32 { return slot*2 + buffer }

// Publication is one compiled policy of one slot.
type Publication struct {
	Slot uint32
	// Generation is unique per publication (nonzero). Verdicts carry it.
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
	if state == nil || state.Type() != ebpf.Array || state.KeySize() != 4 || state.ValueSize() != 16 ||
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
// On any error the slot keeps its last-good policy.
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
	if p.Slot >= b.config.Slots || p.Generation == 0 || p.Write == nil || p.Delete == nil {
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
		return errors.Join(fmt.Errorf("publishing slot %d: %w", p.Slot, err), p.Delete(b.publish, storage))
	}
	first := r == nil || !r.published
	if !first && r.strict != p.Strict && p.Strict {
		// Audit to Strict: the bindings claim Strict before the flip.
		if err := b.rewriteClass(p.Slot, true); err != nil {
			return errors.Join(err, b.rewriteClass(p.Slot, r.strict), p.Delete(b.publish, storage))
		}
	}
	if err := b.slotState.Put(p.Slot, SlotState{Active: buffer, Generation: p.Generation}); err != nil {
		err = fmt.Errorf("flipping slot %d: %w", p.Slot, err)
		if !first && r.strict != p.Strict {
			err = errors.Join(err, b.rewriteClass(p.Slot, r.strict))
		}
		return errors.Join(err, p.Delete(b.publish, storage))
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
		// Audit for a Strict policy.
		return b.rewriteClass(p.Slot, false)
	}
	return nil
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
	if b.armed != nil {
		for _, c := range b.active {
			if c.Slot == slot && !c.SkipArming {
				if err := b.armExisting(b.armed, c.Container.CgroupPath); err != nil && !errors.Is(err, ErrContainerGone) {
					return err
				}
			}
		}
	}
	r.faultBase = count
	return nil
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
