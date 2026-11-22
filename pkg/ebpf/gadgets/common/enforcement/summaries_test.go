// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"sort"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

// The Go layouts match struct verdict_summary_key and struct verdict_summary
// in ../verdict.h (the map layout check in Start compares the same sizes).
func TestSummaryLayout(t *testing.T) {
	if unsafe.Sizeof(summaryKey{}) != summaryKeySize || unsafe.Sizeof(summaryValue{}) != summaryValueSize {
		t.Fatalf("key %d value %d", unsafe.Sizeof(summaryKey{}), unsafe.Sizeof(summaryValue{}))
	}
}

// fakeSummaries is a summaryMap whose keys come out in insertion order.
type fakeSummaries struct {
	keys   []summaryKey
	values map[summaryKey]summaryValue
}

func (m *fakeSummaries) NextKey(key, out interface{}) error {
	if key != nil || len(m.keys) == 0 {
		return ebpf.ErrKeyNotExist
	}
	*out.(*summaryKey) = m.keys[0]
	return nil
}

func (m *fakeSummaries) LookupAndDelete(key, out interface{}) error {
	k := *key.(*summaryKey)
	v, ok := m.values[k]
	if !ok {
		m.keys = m.keys[1:] // vanished (LRU)
		return ebpf.ErrKeyNotExist
	}
	*out.(*summaryValue) = v
	delete(m.values, k)
	m.keys = m.keys[1:]
	return nil
}

func summaryComm(s string) (c [16]byte) {
	copy(c[:], s)
	return c
}

// A drain reads each summary once, converts the boot clock, trims the task
// names, decodes mode and reason, and stops at max. A key that vanishes
// between the two calls (LRU) is skipped.
func TestDrainSummaries(t *testing.T) {
	flood := summaryKey{Cgroup: 7, Generation: 5, Slot: 1, RuleID: 2, Hook: 3, Mode: 2, Reason: 1}
	hidden := summaryKey{Cgroup: 7, Generation: 5, Slot: 1, RuleID: 4, Hook: 3, IsDefault: 1, Mode: 1, Reason: lostDropped}
	gone := summaryKey{Cgroup: 8}
	m := &fakeSummaries{keys: []summaryKey{flood, gone, hidden}, values: map[summaryKey]summaryValue{
		flood:  {Count: 4900, FirstNs: 10e9, LastNs: 11e9, FirstPID: 40, LastPID: 41, FirstComm: summaryComm("perl"), LastComm: summaryComm("perl2")},
		hidden: {Count: 1, FirstNs: 10.5e9, LastNs: 10.5e9, FirstPID: 42, LastPID: 42, FirstComm: summaryComm("hidden"), LastComm: summaryComm("hidden")},
	}}
	wall := time.Unix(1000, 0)
	boot := func() (time.Time, time.Duration) { return wall, 20 * time.Second }
	got, err := drainSummaries(m, 1, boot)
	if err != nil || len(got) != 1 {
		t.Fatalf("max 1: %+v %v", got, err)
	}
	rest, err := drainSummaries(m, 10, boot)
	if err != nil || len(rest) != 1 {
		t.Fatalf("the rest, the vanished key skipped: %+v %v", rest, err)
	}
	got = append(got, rest...)
	sort.Slice(got, func(i, j int) bool { return got[i].RuleID < got[j].RuleID })
	f, h := got[0], got[1]
	if f.FirstComm != "perl" || f.LastComm != "perl2" || f.FirstPID != 40 || f.LastPID != 41 || f.Count != 4900 || !f.Enforce ||
		!f.RateLimited || f.IsDefault || f.Generation != 5 || f.Hook != 3 || f.Slot != 1 || f.CgroupID != 7 {
		t.Fatalf("flood %+v", f)
	}
	if !f.First.Equal(wall.Add(-10*time.Second)) || !f.Last.Equal(wall.Add(-9*time.Second)) {
		t.Fatalf("times %v %v", f.First, f.Last)
	}
	if h.FirstComm != "hidden" || h.Enforce || h.RateLimited || !h.IsDefault || h.Count != 1 {
		t.Fatalf("hidden %+v", h)
	}
	if again, err := drainSummaries(m, 10, boot); err != nil || len(again) != 0 {
		t.Fatalf("drained: %+v %v", again, err)
	}
	var b Bindings
	if _, err := b.DrainVerdictSummaries(10); err == nil {
		t.Fatal("no map must be an error")
	}
	b.summaries, b.stopped = m, true
	if _, err := b.DrainVerdictSummaries(10); err == nil {
		t.Fatal("a stopped controller must not drain")
	}
}
