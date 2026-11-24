package startgate

import (
	"math"
	"testing"
	"time"
)

func TestWorkDeadline(t *testing.T) {
	start := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		parent time.Time
		want   time.Duration
	}{
		{"runtime only", time.Time{}, 900 * time.Millisecond},
		{"earlier parent", start.Add(600 * time.Millisecond), 500 * time.Millisecond},
		{"equal parent", start.Add(time.Second), 900 * time.Millisecond},
		{"later parent cannot extend", start.Add(2 * time.Second), 900 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WorkDeadline(start, time.Second, 100*time.Millisecond, tc.parent)
			if err != nil || !got.Equal(start.Add(tc.want)) {
				t.Fatalf("WorkDeadline = %v, %v; want %v", got, err, start.Add(tc.want))
			}
			if got.After(start.Add(900*time.Millisecond)) || (!tc.parent.IsZero() && got.After(tc.parent.Add(-100*time.Millisecond))) {
				t.Fatal("work deadline extended a budget or spent the return margin")
			}
		})
	}
}

func TestWorkDeadlineRejectsInvalidOrExhaustedBudget(t *testing.T) {
	start := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name            string
		start           time.Time
		timeout, margin time.Duration
		parent          time.Time
	}{
		{"zero start", time.Time{}, time.Second, time.Millisecond, time.Time{}},
		{"zero timeout", start, 0, time.Millisecond, time.Time{}},
		{"negative timeout", start, -1, time.Millisecond, time.Time{}},
		{"minimum timeout", start, math.MinInt64, time.Millisecond, time.Time{}},
		{"zero margin", start, time.Second, 0, time.Time{}},
		{"negative margin", start, time.Second, -1, time.Time{}},
		{"minimum margin", start, time.Second, math.MinInt64, time.Time{}},
		{"margin equals timeout", start, time.Second, time.Second, time.Time{}},
		{"margin exceeds timeout", start, time.Second, 2 * time.Second, time.Time{}},
		{"expired parent", start, time.Second, time.Millisecond, start.Add(-time.Second)},
		{"parent consumed by margin", start, time.Second, time.Millisecond, start.Add(time.Millisecond)},
		{"parent shorter than margin", start, time.Second, time.Millisecond, start.Add(time.Microsecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WorkDeadline(tc.start, tc.timeout, tc.margin, tc.parent)
			if err == nil || !got.IsZero() {
				t.Fatalf("invalid timing inputs returned %v, %v", got, err)
			}
		})
	}
}

func TestWorkDeadlineMaximumDurationDoesNotOverflowSubtraction(t *testing.T) {
	start := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	got, err := WorkDeadline(start, math.MaxInt64, math.MaxInt64-1, time.Time{})
	if err != nil || !got.Equal(start.Add(time.Nanosecond)) {
		t.Fatalf("maximum duration budget = %v, %v", got, err)
	}
}
