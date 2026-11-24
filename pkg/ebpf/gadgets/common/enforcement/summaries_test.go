// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"errors"
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

// fakeSummaries is a summaryMap that returns its entries in order, in
// batches of at most the output size; err is returned once when set.
type fakeSummaries struct {
	keys   []summaryKey
	values map[summaryKey]summaryValue
	err    error
}

func (m *fakeSummaries) BatchLookupAndDelete(_ *ebpf.MapBatchCursor, keysOut, valuesOut any, _ *ebpf.BatchOptions) (int, error) {
	if m.err != nil {
		err := m.err
		m.err = nil
		return 0, err
	}
	ko, vo := keysOut.([]summaryKey), valuesOut.([]summaryValue)
	n := 0
	for n < len(ko) && len(m.keys) > 0 {
		k := m.keys[0]
		m.keys = m.keys[1:]
		ko[n], vo[n] = k, m.values[k]
		delete(m.values, k)
		n++
	}
	if len(m.keys) == 0 {
		return n, ebpf.ErrKeyNotExist
	}
	return n, nil
}

func summaryComm(s string) (c [16]byte) {
	copy(c[:], s)
	return c
}

// A drain reads each summary once, converts the boot clock, trims the task
// names, decodes mode, reason and detail, and stops at max.
func TestDrainSummaries(t *testing.T) {
	flood := summaryKey{Cgroup: 7, Generation: 5, Slot: 1, RuleID: 2, Hook: 3, Detail: 21 | 1<<8, Mode: 2, Reason: 1}
	hidden := summaryKey{Cgroup: 7, Generation: 5, Slot: 1, RuleID: 4, Hook: 3, Detail: 7, IsDefault: 1, Mode: 1, Reason: lostDropped}
	m := &fakeSummaries{keys: []summaryKey{flood, hidden}, values: map[summaryKey]summaryValue{
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
		t.Fatalf("the rest: %+v %v", rest, err)
	}
	got = append(got, rest...)
	sort.Slice(got, func(i, j int) bool { return got[i].RuleID < got[j].RuleID })
	f, h := got[0], got[1]
	if f.FirstComm != "perl" || f.LastComm != "perl2" || f.FirstPID != 40 || f.LastPID != 41 || f.Count != 4900 || !f.Enforce ||
		!f.RateLimited || f.IsDefault || f.Generation != 5 || f.Hook != 3 || f.Detail != 21|1<<8 || f.Slot != 1 || f.CgroupID != 7 {
		t.Fatalf("flood %+v", f)
	}
	if !f.First.Equal(wall.Add(-10*time.Second)) || !f.Last.Equal(wall.Add(-9*time.Second)) {
		t.Fatalf("times %v %v", f.First, f.Last)
	}
	if h.FirstComm != "hidden" || h.Enforce || h.RateLimited || !h.IsDefault || h.Count != 1 || h.Detail != 7 {
		t.Fatalf("hidden %+v", h)
	}
	if again, err := drainSummaries(m, 10, boot); err != nil || len(again) != 0 {
		t.Fatalf("drained: %+v %v", again, err)
	}
	m.err = errors.New("EBADF")
	if _, err := drainSummaries(m, 10, boot); err == nil {
		t.Fatal("a failed batch must be an error")
	}
	var b Bindings
	if _, err := b.DrainVerdictSummaries(10); err == nil {
		t.Fatal("no map must be an error")
	}
}

// Stop drains once more: the summaries of a stopping instance are returned
// by the next drain, once.
func TestStopKeepsLastSummaries(t *testing.T) {
	k := summaryKey{Cgroup: 7, RuleID: 2}
	var b Bindings
	b.summaries = &fakeSummaries{keys: []summaryKey{k}, values: map[summaryKey]summaryValue{k: {Count: 3}}}
	if err := b.Stop(nil); err != nil {
		t.Fatal(err)
	}
	got, err := b.DrainVerdictSummaries(10)
	if err != nil || len(got) != 1 || got[0].Count != 3 {
		t.Fatalf("after stop: %+v %v", got, err)
	}
	if _, err := b.DrainVerdictSummaries(10); err == nil {
		t.Fatal("once only")
	}
}
