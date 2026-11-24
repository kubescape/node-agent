// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"testing"

	"github.com/cilium/ebpf"
)

// A previous run's counters map has 6 slots (an image built before the
// summary overflow slot) or 7: both are read; a map of another size is not a
// counters map. Needs CAP_BPF (skips otherwise).
func TestPinnedSetCountersSlots(t *testing.T) {
	mapOf := func(t *testing.T, entries uint32) PinnedSet {
		t.Helper()
		m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "counters", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: entries})
		if err != nil {
			t.Skipf("cannot create a BPF map here: %v", err)
		}
		t.Cleanup(func() { m.Close() })
		cpus, err := ebpf.PossibleCPU()
		if err != nil {
			t.Fatal(err)
		}
		for i := uint32(0); i < entries; i++ {
			values := make([]uint64, cpus)
			values[0] = uint64(i + 1)
			if err := m.Put(i, values); err != nil {
				t.Fatal(err)
			}
		}
		info, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := info.ID()
		return PinnedSet{Manifest: PinManifest{MapIDs: []uint32{uint32(id)}}}
	}
	got, err := PinnedSetCounters(mapOf(t, verdictCounterBase))
	if err != nil || got.RateLimited != 6 || got.Dropped != 3 || got.SummaryOverflow != 0 {
		t.Fatalf("6 slots: %+v %v", got, err)
	}
	got, err = PinnedSetCounters(mapOf(t, verdictCounterCount))
	if err != nil || got.RateLimited != 6 || got.SummaryOverflow != 7 {
		t.Fatalf("7 slots: %+v %v", got, err)
	}
	if _, err := PinnedSetCounters(mapOf(t, 5)); err == nil {
		t.Fatal("5 slots is not a counters map")
	}
}
