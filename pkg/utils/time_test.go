package utils

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAddJitter(t *testing.T) {
	tests := []struct {
		name       string
		duration   time.Duration
		percentage int
	}{
		{name: "no jitter", duration: 24 * time.Hour, percentage: 0},
		{name: "default 5 percent", duration: 24 * time.Hour, percentage: 5},
		{name: "small duration", duration: time.Second, percentage: 10},
		{name: "100 percent", duration: time.Minute, percentage: 100},
		{name: "negative percentage", duration: time.Minute, percentage: -5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maxJitter := max(tt.duration*time.Duration(tt.percentage)/100, 0)
			seen := map[time.Duration]struct{}{}
			for range 1000 {
				got := AddJitter(tt.duration, tt.percentage)
				assert.GreaterOrEqual(t, got, tt.duration)
				assert.LessOrEqual(t, got, tt.duration+maxJitter)
				seen[got] = struct{}{}
			}
			if tt.percentage > 0 {
				assert.Greater(t, len(seen), 1, "jitter must vary across calls")
			} else {
				assert.Len(t, seen, 1, "no jitter")
			}
		})
	}
}

func TestAddJitter_NoOverflow(t *testing.T) {
	huge := time.Duration(math.MaxInt64 - 10)
	for _, p := range []int{5, 100, 1000} {
		for range 100 {
			got := AddJitter(huge, p)
			assert.GreaterOrEqual(t, got, huge, "percentage %d", p)
		}
	}
	assert.Equal(t, time.Duration(0), AddJitter(0, 5))
}
