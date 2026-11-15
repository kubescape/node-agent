// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"fmt"
	"math"
	"time"
)

// Runtime reporting rule, after FailClosedRate of the enforce_exec reference
// (gadgets/enforce_exec/fullruntime/fail_closed_rate.go in the IG fork):
//   - Degraded on any fail-closed refusal (Strict) or unevaluated judgement
//     (Audit) within DegradedWindow;
//   - NotReady when the failure rate is above NotReadyThreshold over
//     NotReadyWindow;
//   - unknown, never zero, when a counter is unreadable or moved backwards.
const (
	DegradedWindow    = time.Minute
	DegradedThreshold = 0.0
	NotReadyWindow    = 5 * time.Minute
	NotReadyThreshold = 0.001
)

// RateSample is one read of the counters that a rate is computed from. Each
// failure counter is a class (for example faults, unevaluated judgements,
// node faults, exempted execs); Attempts is the denominator and includes
// every attempt a failure class counts.
type RateSample struct {
	At       time.Time
	Failures []uint64
	Attempts uint64
}

// RateVerdict is the verdict for one window.
type RateVerdict struct {
	Failures uint64
	Attempts uint64
	Rate     float64
	// Degraded: Failures is nonzero and Rate is above the threshold (a
	// threshold of 0 degrades on any failure).
	Degraded bool
}

// FailRate maps two samples to a verdict. A counter that moved backwards or
// a changed set of classes is an error (the verdict is unknown), never a zero
// rate.
func FailRate(before, after RateSample, threshold float64) (RateVerdict, error) {
	var v RateVerdict
	if math.IsNaN(threshold) || threshold < 0 || threshold > 1 {
		return v, fmt.Errorf("fail rate threshold %v outside [0, 1]", threshold)
	}
	if len(before.Failures) != len(after.Failures) {
		return v, fmt.Errorf("fail rate samples have %d and %d classes", len(before.Failures), len(after.Failures))
	}
	if after.Attempts < before.Attempts {
		return v, fmt.Errorf("attempt counter moved backwards (%d -> %d)", before.Attempts, after.Attempts)
	}
	for i := range after.Failures {
		if after.Failures[i] < before.Failures[i] {
			return v, fmt.Errorf("failure counter %d moved backwards (%d -> %d)", i, before.Failures[i], after.Failures[i])
		}
		d := after.Failures[i] - before.Failures[i]
		if v.Failures+d < v.Failures {
			return v, fmt.Errorf("fail rate total overflows")
		}
		v.Failures += d
	}
	v.Attempts = after.Attempts - before.Attempts
	// A sample reads its counters one after another: an attempt counted in
	// one sample can have its failure in the next. A window can then hold
	// a few more failures than attempts; count each failure as an attempt
	// (the rate stays high, never zero).
	if v.Failures > v.Attempts {
		v.Attempts = v.Failures
	}
	if v.Attempts > 0 {
		v.Rate = float64(v.Failures) / float64(v.Attempts)
	}
	v.Degraded = v.Failures > 0 && v.Rate > threshold
	return v, nil
}

// RateReport is the reporting rule applied to a window.
type RateReport struct {
	// Unknown is set when the counters cannot prove the state: a read
	// failed, a counter moved backwards, or there is not yet one
	// DegradedWindow of history since the last such event. Degraded and
	// NotReady are then not decided.
	Unknown  error
	Degraded bool
	NotReady bool
	// Last is the verdict over the Degraded window, Long over the NotReady
	// window (as much of it as there is).
	Last, Long RateVerdict
}

// RateWindow keeps the samples of one key (a section's slot, or a node
// witness) for NotReadyWindow. It belongs to the owner, not to an instance:
// it keeps its samples across instance generations, heals and reloads, so a
// failure stays visible for its window whatever was reloaded. Not safe for
// concurrent use.
type RateWindow struct {
	samples []RateSample
	// unknown: why the state is unknown since unknownAt.
	unknown   error
	unknownAt time.Time
}

// Add records a sample, or a read error. A sample with a counter lower than
// the previous one starts a new history: the earlier samples cannot be
// compared with it.
func (w *RateWindow) Add(s RateSample, readErr error) {
	if readErr != nil {
		w.unknown, w.unknownAt = fmt.Errorf("counters unreadable: %w", readErr), s.At
		return
	}
	if n := len(w.samples); n > 0 && backwards(w.samples[n-1], s) {
		w.samples = nil
		w.unknown, w.unknownAt = fmt.Errorf("counters moved backwards (reset or reload)"), s.At
	}
	w.samples = append(w.samples, s)
	// Keep one sample at or before the long window's start.
	cut := 0
	for i := range w.samples {
		if s.At.Sub(w.samples[i].At) >= NotReadyWindow {
			cut = i
		}
	}
	w.samples = w.samples[cut:]
}

func backwards(a, b RateSample) bool {
	if b.Attempts < a.Attempts || len(a.Failures) != len(b.Failures) {
		return true
	}
	for i := range a.Failures {
		if b.Failures[i] < a.Failures[i] {
			return true
		}
	}
	return false
}

// Report applies the rule at now. The Degraded window compares the newest
// sample with the newest one at least DegradedWindow older; the NotReady
// window with the oldest kept. An unknown state lasts until a full Degraded
// window of samples follows it.
func (w *RateWindow) Report(now time.Time) RateReport {
	var r RateReport
	if w.unknown != nil && now.Sub(w.unknownAt) < DegradedWindow {
		r.Unknown = w.unknown
		return r
	}
	n := len(w.samples)
	if n == 0 {
		r.Unknown = fmt.Errorf("no counter sample")
		return r
	}
	newest := w.samples[n-1]
	if now.Sub(newest.At) > DegradedWindow {
		r.Unknown = fmt.Errorf("no counter sample since %s", newest.At.Format(time.RFC3339))
		return r
	}
	if newest.At.Sub(w.samples[0].At) < DegradedWindow {
		r.Unknown = fmt.Errorf("less than %s of counter samples", DegradedWindow)
		return r
	}
	base := w.samples[0]
	for _, s := range w.samples {
		if newest.At.Sub(s.At) >= DegradedWindow {
			base = s
		}
	}
	var err error
	if r.Last, err = FailRate(base, newest, DegradedThreshold); err != nil {
		r.Unknown = err
		return r
	}
	if r.Long, err = FailRate(w.samples[0], newest, NotReadyThreshold); err != nil {
		r.Unknown = err
		return r
	}
	r.Degraded, r.NotReady = r.Last.Degraded, r.Long.Degraded
	return r
}
