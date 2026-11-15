// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// SlotCounters are the raw reporting counters of one slot (../arming.h). They
// live in the section's pinned maps, so they keep counting across heals,
// reloads and restarts; a FailRate window reads their deltas. A counter that
// is lower than an earlier read moved backwards (the maps were created again).
type SlotCounters struct {
	// Faults: fail-closed refusals and tracking faults of Strict bindings
	// (arming_faults, never reset by a heal).
	Faults uint64
	// Unevaluated: judgements an Audit binding lost.
	Unevaluated uint64
	// Attempts: judged checks and forks of armed tasks (the denominator).
	Attempts uint64
}

// NodeCounters are the raw node-wide witness counters (arming_witness).
type NodeCounters struct {
	NodeFaults  uint64
	ExemptExecs uint64
}

// Counters reads the raw counters of a slot. Any unreadable counter is an
// error: unknown, never zero.
func (b *Bindings) Counters(slot uint32) (SlotCounters, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.faults == nil || b.attempts == nil || b.unevaluated == nil {
		return SlotCounters{}, fmt.Errorf("%s: reporting counters are not configured", b.config.Name)
	}
	var c SlotCounters
	if err := b.faults.Lookup(slot, &c.Faults); err != nil {
		return SlotCounters{}, fmt.Errorf("reading slot %d faults: %w", slot, err)
	}
	if err := b.unevaluated.Lookup(slot, &c.Unevaluated); err != nil {
		return SlotCounters{}, fmt.Errorf("reading slot %d unevaluated judgements: %w", slot, err)
	}
	var perCPU []uint64
	if err := b.attempts.Lookup(slot, &perCPU); err != nil {
		return SlotCounters{}, fmt.Errorf("reading slot %d attempts: %w", slot, err)
	}
	for _, n := range perCPU {
		c.Attempts += n
	}
	return c, nil
}

// NodeCounters reads the raw witness counters (no heal base).
func (b *Bindings) NodeCounters() (NodeCounters, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.witness == nil {
		return NodeCounters{}, fmt.Errorf("%s: no witness map configured", b.config.Name)
	}
	var c NodeCounters
	if err := b.witness.Lookup(uint32(0), &c.NodeFaults); err != nil {
		return NodeCounters{}, fmt.Errorf("reading node faults: %w", err)
	}
	if err := b.witness.Lookup(uint32(1), &c.ExemptExecs); err != nil {
		return NodeCounters{}, fmt.Errorf("reading exempted execs: %w", err)
	}
	return c, nil
}

// counterMaps loads the reporting counter maps of Config.AttemptsMap and
// Config.UnevaluatedMap.
func (b *Bindings) counterMaps(getPinned func(string) (*ebpf.Map, error)) error {
	if b.config.AttemptsMap == "" && b.config.UnevaluatedMap == "" {
		return nil
	}
	attempts, err := getPinned(b.config.AttemptsMap)
	if err != nil {
		return err
	}
	if attempts.Type() != ebpf.PerCPUArray || attempts.KeySize() != 4 || attempts.ValueSize() != 8 || attempts.MaxEntries() < b.config.Slots {
		return fmt.Errorf("invalid attempts map layout")
	}
	unevaluated, err := getPinned(b.config.UnevaluatedMap)
	if err != nil {
		return err
	}
	if unevaluated.Type() != ebpf.Array || unevaluated.KeySize() != 4 || unevaluated.ValueSize() != 8 || unevaluated.MaxEntries() < b.config.Slots {
		return fmt.Errorf("invalid unevaluated map layout")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attempts, b.unevaluated = attempts, unevaluated
	return nil
}
