// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"testing"
	"time"
)

func TestFailRate(t *testing.T) {
	at := time.Unix(0, 0)
	s := func(f, a uint64) RateSample { return RateSample{At: at, Failures: []uint64{f, 0}, Attempts: a} }
	if v, err := FailRate(s(1, 100), s(2, 200), 0); err != nil || !v.Degraded || v.Failures != 1 {
		t.Fatalf("one failure at threshold 0: %+v %v", v, err)
	}
	if v, err := FailRate(s(1, 100), s(2, 2100), 0.001); err != nil || v.Degraded {
		t.Fatalf("1 in 2000 is under 0.1%%: %+v %v", v, err)
	}
	if v, err := FailRate(s(1, 100), s(1, 100), 0); err != nil || v.Degraded {
		t.Fatalf("no failure: %+v %v", v, err)
	}
	for name, pair := range map[string][2]RateSample{
		"failure backwards":  {s(2, 100), s(1, 200)},
		"attempts backwards": {s(1, 200), s(1, 100)},
		"classes changed":    {s(0, 0), {At: at, Failures: []uint64{0}}},
	} {
		if _, err := FailRate(pair[0], pair[1], 0); err == nil {
			t.Errorf("%s: want unknown, got a verdict", name)
		}
	}
	if v, err := FailRate(s(0, 0), s(3, 2), 0); err != nil || v.Attempts != 3 || v.Rate != 1 {
		t.Fatalf("a failure read before its attempt counts as one: %+v %v", v, err)
	}
	if _, err := FailRate(s(0, 0), s(0, 0), 2); err == nil {
		t.Error("threshold above 1 must be refused")
	}
}

// sampler feeds a window one sample every 10 s.
type sampler struct {
	w   RateWindow
	now time.Time
	f   uint64
	a   uint64
}

func (s *sampler) run(d time.Duration, failures, attempts uint64) {
	for end := s.now.Add(d); s.now.Before(end); {
		s.now = s.now.Add(10 * time.Second)
		s.f += failures
		s.a += attempts
		s.w.Add(RateSample{At: s.now, Failures: []uint64{s.f}, Attempts: s.a}, nil)
	}
}

func TestRateWindowRule(t *testing.T) {
	s := &sampler{now: time.Unix(1000, 0)}
	s.run(30*time.Second, 0, 100)
	if r := s.w.Report(s.now); r.Unknown == nil {
		t.Fatalf("less than 60 s of history must be unknown: %+v", r)
	}
	s.run(time.Minute, 0, 100)
	if r := s.w.Report(s.now); r.Unknown != nil || r.Degraded || r.NotReady {
		t.Fatalf("clean minute: %+v", r)
	}
	// One failure: Degraded for 60 s, under the NotReady threshold.
	s.f++
	s.run(10*time.Second, 0, 1000)
	if r := s.w.Report(s.now); !r.Degraded || r.NotReady {
		t.Fatalf("one failure in 60 s: %+v", r)
	}
	s.run(70*time.Second, 0, 1000)
	if r := s.w.Report(s.now); r.Degraded || r.NotReady || r.Unknown != nil {
		t.Fatalf("failure older than 60 s, low rate: %+v", r)
	}
	// A rate above 0.1 % over 5 min is NotReady even after the last 60 s are
	// clean.
	s.run(time.Minute, 5, 1000)
	s.run(70*time.Second, 0, 1000)
	if r := s.w.Report(s.now); r.Degraded || !r.NotReady {
		t.Fatalf("rate above 0.1%% over 5 min: %+v (long %+v)", r, r.Long)
	}
}

func TestRateWindowUnknownNeverZero(t *testing.T) {
	s := &sampler{now: time.Unix(1000, 0)}
	s.run(2*time.Minute, 0, 100)
	// A heal or reload never resets the raw counters; a counter lower than
	// before means the maps were created again: unknown, not a fresh zero.
	s.f, s.a = 0, 0
	s.run(10*time.Second, 0, 100)
	if r := s.w.Report(s.now); r.Unknown == nil {
		t.Fatalf("backwards counter: %+v", r)
	}
	s.run(time.Minute, 0, 100)
	if r := s.w.Report(s.now); r.Unknown != nil {
		t.Fatalf("a full window after the reset decides again: %+v", r)
	}
	s.w.Add(RateSample{At: s.now}, errUnreadable)
	if r := s.w.Report(s.now); r.Unknown == nil {
		t.Fatalf("unreadable counter: %+v", r)
	}
	if r := s.w.Report(s.now.Add(3 * time.Minute)); r.Unknown == nil {
		t.Fatalf("no recent sample: %+v", r)
	}
}

// A read error stays unknown until a full Degraded window of readable samples
// follows it, even when older samples already span the window.
func TestRateWindowUnknownUntilFullWindowAfterReadError(t *testing.T) {
	s := &sampler{now: time.Unix(1000, 0)}
	s.run(time.Minute, 0, 100)
	s.now = s.now.Add(10 * time.Second)
	s.w.Add(RateSample{At: s.now}, errUnreadable)
	s.run(time.Minute, 0, 100)
	if r := s.w.Report(s.now); r.Unknown == nil {
		t.Fatalf("less than a full window of samples after the error must be unknown: %+v", r)
	}
	s.run(time.Minute, 0, 100)
	if r := s.w.Report(s.now); r.Unknown != nil {
		t.Fatalf("a full window after the error decides again: %+v", r)
	}
}

var errUnreadable = errorString("map lookup failed")

type errorString string

func (e errorString) Error() string { return string(e) }

// Notices make the Degraded window true but never count in the rate.
func TestRateWindowNotices(t *testing.T) {
	var w RateWindow
	now := time.Unix(1000, 0)
	notices := uint64(0)
	for i := 0; i < 20; i++ {
		now = now.Add(10 * time.Second)
		if i == 18 {
			notices++
		}
		w.Add(RateSample{At: now, Failures: []uint64{0}, Attempts: uint64(i), Notices: notices}, nil)
	}
	r := w.Report(now)
	if r.Unknown != nil || !r.Degraded || r.NotReady || r.Notices != 1 {
		t.Fatalf("a notice: %+v", r)
	}
}
