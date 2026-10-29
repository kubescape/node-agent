package utils

import (
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maxJitter := tt.duration * time.Duration(tt.percentage) / 100
			jittered := false
			for range 1000 {
				got := AddJitter(tt.duration, tt.percentage)
				assert.GreaterOrEqual(t, got, tt.duration)
				assert.LessOrEqual(t, got, tt.duration+maxJitter)
				if got != tt.duration {
					jittered = true
				}
			}
			assert.Equal(t, tt.percentage > 0, jittered, "jitter applied")
		})
	}
}
