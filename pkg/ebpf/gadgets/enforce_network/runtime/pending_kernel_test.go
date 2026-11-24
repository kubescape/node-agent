//go:build linux && network_kernel

// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/kubescape/node-agent/pkg/ebpf/gadgets/common/enforcement"
)

// Same fixture and environment as runtime_kernel_test.go.

// bindingEntry is struct sandbox_binding of ../../common/bindings.h.
type bindingEntry struct{ Slot, Flags uint32 }

// bindingStrictFlag is BINDING_STRICT of ../../common/bindings.h.
const bindingStrictFlag = 1 << 1

func pinnedBindings(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(enforcement.PinRoot, MapPrefix+enforcement.BindingsMap), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func pinnedBinding(t *testing.T, m *ebpf.Map, cgroup uint64) bindingEntry {
	t.Helper()
	var v bindingEntry
	if err := m.Lookup(cgroup, &v); err != nil {
		t.Fatalf("binding of cgroup %d: %v", cgroup, err)
	}
	return v
}

// TestPendingSlotKernel binds the fixture container to PendingSlot, a slot
// that is never published (the start gate's mark). Strict: a connect is a
// structural fault, denied with EPERM. Audit: the kernel alone decides.
// Both count only in the node-wide SECTION_ERROR counter. Then one bind moves
// the entry to the published slot 1 (default deny, loopback allowed), whose
// rules decide from then on.
func TestPendingSlotKernel(t *testing.T) {
	f := newKernelFixture(t)
	if err := f.start(t, matrixPolicy(t)); err != nil {
		t.Fatal(err)
	}
	m := pinnedBindings(t)
	loopback := f.call(t, f.id, "tcp4", "127.0.0.1", 9) // the kernel alone, unbound
	if loopback == "EPERM" {
		t.Fatalf("unbound loopback connect = %s", loopback)
	}
	sectionErrors := func() uint64 {
		t.Helper()
		c, err := f.bindings.VerdictCounters()
		if err != nil {
			t.Fatal(err)
		}
		return c.SectionErrors
	}
	t.Cleanup(func() { f.bindings.Unbind(f.container) })

	// Strict pending: EPERM, a section error.
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: enforcement.PendingSlot, Strict: true}); err != nil {
		t.Fatal(err)
	}
	if v := pinnedBinding(t, m, f.container.CgroupID); v.Slot != enforcement.PendingSlot || v.Flags&bindingStrictFlag == 0 {
		t.Fatalf("Strict pending entry: %+v", v)
	}
	before := sectionErrors()
	f.expect(t, f.id, "tcp4", "127.0.0.1", 9, "EPERM")
	after := sectionErrors()
	t.Logf("Strict pending: section errors %d -> %d", before, after)
	if after <= before {
		t.Fatalf("the structural fault counts a section error: %d -> %d", before, after)
	}
	f.waitFault(t)
	if _, err := f.bindings.SlotFaults(enforcement.PendingSlot); err == nil {
		t.Fatal("SlotFaults(PendingSlot) must be an error, never zero")
	}
	if _, err := f.bindings.Counters(enforcement.PendingSlot); err == nil {
		t.Fatal("Counters(PendingSlot) must be an error, never zero")
	}

	// Audit pending: the kernel decides, still a section error.
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: enforcement.PendingSlot}); err != nil {
		t.Fatal(err)
	}
	if v := pinnedBinding(t, m, f.container.CgroupID); v.Slot != enforcement.PendingSlot || v.Flags&bindingStrictFlag != 0 {
		t.Fatalf("Audit pending entry: %+v", v)
	}
	before = sectionErrors()
	f.expect(t, f.id, "tcp4", "127.0.0.1", 9, loopback)
	after = sectionErrors()
	t.Logf("Audit pending: section errors %d -> %d", before, after)
	if after <= before {
		t.Fatalf("the Audit structural fault counts a section error: %d -> %d", before, after)
	}

	// Pending -> slot 1 in one bind: the default deny decides.
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 1}); err != nil {
		t.Fatal(err)
	}
	if v := pinnedBinding(t, m, f.container.CgroupID); v.Slot != 1 || v.Flags&bindingStrictFlag == 0 {
		t.Fatalf("bound entry: %+v", v)
	}
	slotBefore, err := f.bindings.Counters(1)
	if err != nil {
		t.Fatal(err)
	}
	f.expect(t, f.id, "tcp4", "127.0.0.1", 9, loopback)
	f.expect(t, f.id, "tcp4", "192.0.2.7", 80, "EPERM")
	slotAfter, err := f.bindings.Counters(1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("slot 1: counters %+v -> %+v", slotBefore, slotAfter)
	if slotAfter.Faults != slotBefore.Faults || slotAfter.Attempts <= slotBefore.Attempts {
		t.Fatalf("slot 1 judges with no fault: %+v -> %+v", slotBefore, slotAfter)
	}
}

// TestPendingSlotFullMapReplace fills the gadget's own pinned binding map to
// capacity (dummy keys: cgroup IDs no task has), then moves the fixture
// container's entry from PendingSlot to slot 1 with one bind: replacing an
// existing key of a full HASH map must succeed, while a new key is refused.
func TestPendingSlotFullMapReplace(t *testing.T) {
	f := newKernelFixture(t)
	if err := f.start(t, matrixPolicy(t)); err != nil {
		t.Fatal(err)
	}
	m := pinnedBindings(t)
	// The kernel alone, unbound: after the replacement slot 1 allows
	// loopback, where the Strict pending mark denied it.
	loopback := f.call(t, f.id, "tcp4", "127.0.0.1", 9)
	if loopback == "EPERM" {
		t.Fatalf("unbound loopback connect = %s", loopback)
	}
	if m.MaxEntries() != enforcement.MaxBindings {
		t.Fatalf("binding map has %d entries, want %d", m.MaxEntries(), enforcement.MaxBindings)
	}
	t.Cleanup(func() { f.bindings.Unbind(f.container) })
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: enforcement.PendingSlot, Strict: true}); err != nil {
		t.Fatal(err)
	}
	f.expect(t, f.id, "tcp4", "127.0.0.1", 9, "EPERM")

	const dummyBase = uint64(0xFFFF) << 48
	var dummies []uint64
	t.Cleanup(func() {
		for _, k := range dummies {
			_ = m.Delete(k)
		}
	})
	for i := uint64(0); ; i++ {
		k := dummyBase + i
		err := m.Update(k, bindingEntry{Slot: 0}, ebpf.UpdateNoExist)
		if err != nil {
			t.Logf("binding map full after %d dummy keys: %v", len(dummies), err)
			break
		}
		dummies = append(dummies, k)
		if i > enforcement.MaxBindings {
			t.Fatal("the binding map took more keys than its capacity")
		}
	}
	var (
		key     uint64
		value   bindingEntry
		entries int
	)
	for it := m.Iterate(); it.Next(&key, &value); {
		entries++
	}
	t.Logf("binding map: %d entries (%d dummy keys), capacity %d", entries, len(dummies), enforcement.MaxBindings)
	if entries != enforcement.MaxBindings {
		t.Fatalf("the binding map holds %d entries, want it full at %d", entries, enforcement.MaxBindings)
	}
	err := m.Update(dummyBase+uint64(len(dummies))+1, bindingEntry{}, ebpf.UpdateAny)
	t.Logf("a new key on the full map: %v", err)
	if err == nil {
		t.Fatal("a new key must be refused by the full map")
	}

	// The replacement: PendingSlot -> slot 1, one bind.
	if err := f.bindings.Bind(enforcement.Binding{Container: f.container, Slot: 1}); err != nil {
		t.Fatalf("replacing an existing key of a full binding map: %v", err)
	}
	if v := pinnedBinding(t, m, f.container.CgroupID); v.Slot != 1 || v.Flags&bindingStrictFlag == 0 {
		t.Fatalf("replaced entry: %+v", v)
	}
	// The kernel judges with slot 1 now: loopback is back to the kernel's
	// own result (EPERM under the pending mark), other destinations denied.
	f.expect(t, f.id, "tcp4", "127.0.0.1", 9, loopback)
	f.expect(t, f.id, "tcp4", "192.0.2.7", 80, "EPERM")
}
