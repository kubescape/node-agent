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
// (verdict_summaries): a hash map the owner drains key by key.
type summaryMap interface {
	NextKey(key, nextKeyOut interface{}) error
	LookupAndDelete(key, valueOut interface{}) error
}

// summaryKey matches struct verdict_summary_key in ../verdict.h.
type summaryKey struct {
	Cgroup     uint64
	Generation uint64
	Slot       uint32
	RuleID     uint32
	Hook       uint32
	IsDefault  uint8
	Mode       uint8
	Reason     uint8
	_          uint8
}

// summaryValue matches struct verdict_summary in ../verdict.h.
type summaryValue struct {
	Count, FirstNs, LastNs uint64
	FirstPID, LastPID      uint32
	FirstComm, LastComm    [16]byte
}

const (
	summaryKeySize   = 32
	summaryValueSize = 64
	// lostDropped is VERDICT_LOST_DROPPED in ../verdict.h.
	lostDropped = 2
)

// VerdictSummary aggregates the deny verdicts of one key that the kernel
// could not report: past its per-CPU report limit (RateLimited) or with a
// full ring buffer. First and Last are wall-clock times converted from the
// boot clock, with the task (pid, name) of the first and the last lost deny.
// Counts are approximate (see ../verdict.h).
type VerdictSummary struct {
	Generation          uint64
	CgroupID            uint64
	Slot                uint32
	RuleID              uint32
	Hook                uint32
	IsDefault           bool
	Enforce             bool
	RateLimited         bool
	Count               uint64
	First, Last         time.Time
	FirstPID, LastPID   uint32
	FirstComm, LastComm string
}

// DrainVerdictSummaries reads and deletes at most max summaries. A deny lost
// after a key is read starts a new summary for that key. The map is per
// instance: summaries not drained before the instance stops are lost (the
// counters keep their number).
func (b *Bindings) DrainVerdictSummaries(max int) ([]VerdictSummary, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return nil, fmt.Errorf("binding controller stopped")
	}
	if b.summaries == nil {
		return nil, fmt.Errorf("verdict summaries unavailable")
	}
	return drainSummaries(b.summaries, max, bootNow())
}

func drainSummaries(m summaryMap, max int, boot func() (time.Time, time.Duration)) ([]VerdictSummary, error) {
	var out []VerdictSummary
	wall, since := boot()
	at := func(ns uint64) time.Time { return wall.Add(time.Duration(ns) - since) }
	// tries bounds the loop also when keys vanish between the two calls.
	for tries := 0; len(out) < max && tries < 2*max; tries++ {
		var key summaryKey
		// The first key each time: the previous one is deleted.
		if err := m.NextKey(nil, &key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return out, fmt.Errorf("reading verdict summaries: %w", err)
		}
		var v summaryValue
		if err := m.LookupAndDelete(&key, &v); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue // deleted meanwhile (LRU)
			}
			return out, fmt.Errorf("draining a verdict summary: %w", err)
		}
		out = append(out, VerdictSummary{Generation: key.Generation, CgroupID: key.Cgroup, Slot: key.Slot, RuleID: key.RuleID,
			Hook: key.Hook, IsDefault: key.IsDefault != 0, Enforce: key.Mode == 2, RateLimited: key.Reason != lostDropped,
			Count: v.Count, First: at(v.FirstNs), Last: at(v.LastNs), FirstPID: v.FirstPID, LastPID: v.LastPID,
			FirstComm: cString(v.FirstComm[:]), LastComm: cString(v.LastComm[:])})
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
func bootNow() func() (time.Time, time.Duration) {
	return func() (time.Time, time.Duration) {
		var ts unix.Timespec
		_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
		return time.Now(), time.Duration(ts.Nano())
	}
}
