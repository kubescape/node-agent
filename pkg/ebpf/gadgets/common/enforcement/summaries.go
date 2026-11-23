// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// summaryMap is the lost-verdict summary map of ../verdict.h
// (verdict_summaries): a hash map the owner drains in batches.
type summaryMap interface {
	BatchLookupAndDelete(cursor *ebpf.MapBatchCursor, keysOut, valuesOut any, opts *ebpf.BatchOptions) (int, error)
}

// summaryKey matches struct verdict_summary_key in ../verdict.h.
type summaryKey struct {
	Cgroup     uint64
	Generation uint64
	Slot       uint32
	RuleID     uint32
	Hook       uint32
	Detail     uint32
	IsDefault  uint8
	Mode       uint8
	Reason     uint8
	_          [5]uint8
}

// summaryValue matches struct verdict_summary in ../verdict.h.
type summaryValue struct {
	Count, FirstNs, LastNs uint64
	FirstPID, LastPID      uint32
	FirstComm, LastComm    [16]byte
}

const (
	summaryKeySize   = 40
	summaryValueSize = 64
	// summaryKeys is VERDICT_SUMMARY_KEYS in ../verdict.h.
	summaryKeys = 4096
	// summaryBatch is the number of entries one batch call reads.
	summaryBatch = 256
	// lostDropped is VERDICT_LOST_DROPPED in ../verdict.h.
	lostDropped = 2
)

// VerdictSummary aggregates the deny verdicts of one key that the kernel
// could not report: past its per-CPU report limit (RateLimited) or with a
// full ring buffer. Detail is, for privilege, the capability in bits 0-7
// (255 for none) and the syscall from bit 8; for file, the access kind; for
// network, 0. First and Last
// are wall-clock times converted from the boot clock, with the task (pid,
// name) of the first and the last lost deny. Counts are approximate (see
// ../verdict.h).
type VerdictSummary struct {
	Generation          uint64
	CgroupID            uint64
	Slot                uint32
	RuleID              uint32
	Hook                uint32
	Detail              uint32
	IsDefault           bool
	Enforce             bool
	RateLimited         bool
	Count               uint64
	First, Last         time.Time
	FirstPID, LastPID   uint32
	FirstComm, LastComm string
}

// DrainVerdictSummaries reads and deletes at most max summaries. A deny lost
// after a key is read starts a new summary for that key. It holds summaryMu,
// not mu, so Bind and Unbind do not wait for it. After Stop it returns the
// summaries of the last drain once.
func (b *Bindings) DrainVerdictSummaries(max int) ([]VerdictSummary, error) {
	b.summaryMu.Lock()
	defer b.summaryMu.Unlock()
	if b.summaries == nil {
		if b.final != nil {
			out := b.final
			b.final = nil
			return out, nil
		}
		return nil, fmt.Errorf("verdict summaries unavailable")
	}
	boot, err := bootNow()
	if err != nil {
		return nil, err
	}
	return drainSummaries(b.summaries, max, boot)
}

// stopSummaries keeps the summaries of a stopping instance (the map goes
// with it): one last drain, before the controller is marked stopped.
func (b *Bindings) stopSummaries() {
	b.summaryMu.Lock()
	defer b.summaryMu.Unlock()
	if b.summaries == nil {
		return
	}
	if boot, err := bootNow(); err == nil {
		b.final, _ = drainSummaries(b.summaries, summaryKeys, boot)
	}
	b.summaries = nil
}

func drainSummaries(m summaryMap, max int, boot func() (time.Time, time.Duration)) ([]VerdictSummary, error) {
	var out []VerdictSummary
	wall, since := boot()
	at := func(ns uint64) time.Time { return wall.Add(time.Duration(ns) - since) }
	var cursor ebpf.MapBatchCursor
	keys := make([]summaryKey, summaryBatch)
	values := make([]summaryValue, summaryBatch)
	for len(out) < max {
		n, err := m.BatchLookupAndDelete(&cursor, keys[:min(summaryBatch, max-len(out))], values[:min(summaryBatch, max-len(out))], nil)
		for i := range n {
			k, v := keys[i], values[i]
			out = append(out, VerdictSummary{Generation: k.Generation, CgroupID: k.Cgroup, Slot: k.Slot, RuleID: k.RuleID,
				Hook: k.Hook, Detail: k.Detail, IsDefault: k.IsDefault != 0, Enforce: k.Mode == 2, RateLimited: k.Reason != lostDropped,
				Count: v.Count, First: at(v.FirstNs), Last: at(v.LastNs), FirstPID: v.FirstPID, LastPID: v.LastPID,
				FirstComm: cString(v.FirstComm[:]), LastComm: cString(v.LastComm[:])})
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break // the map is drained
		}
		if err != nil {
			return out, fmt.Errorf("draining verdict summaries: %w", err)
		}
		if n == 0 {
			break
		}
	}
	return out, nil
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// bootNow returns the wall clock and the boot clock read together.
func bootNow() (func() (time.Time, time.Duration), error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return nil, fmt.Errorf("reading the boot clock: %w", err)
	}
	wall, since := time.Now(), time.Duration(ts.Nano())
	return func() (time.Time, time.Duration) { return wall, since }, nil
}
