package exporters

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The alert limit used to stop limiting after its first drop: the notified flag
// cleared the condition, so the exporter dropped one alert per minute and sent
// every later one. This pins the fixed behaviour — once the limit is spent, every
// further alert in the window is dropped, and the notice is decided once.
func TestAlertLimitKeepsLimitingAfterTheFirstDrop(t *testing.T) {
	e := &HTTPExporter{
		config:       HTTPExporterConfig{MaxAlertsPerMinute: 1},
		alertMetrics: &alertMetrics{},
	}

	admitted, notify := e.admitAlert()
	assert.True(t, admitted, "the first alert is inside the limit")
	assert.False(t, notify)

	admitted, notify = e.admitAlert()
	assert.False(t, admitted, "the second alert is past the limit")
	assert.True(t, notify, "and it triggers the one notice")

	for i := 0; i < 5; i++ {
		admitted, notify = e.admitAlert()
		assert.False(t, admitted, "alert %d must stay dropped inside the window", i+3)
		assert.False(t, notify, "the notice is sent once per window")
	}
}

// A new window admits alerts again.
func TestAlertLimitResetsWithTheWindow(t *testing.T) {
	e := &HTTPExporter{
		config:       HTTPExporterConfig{MaxAlertsPerMinute: 1},
		alertMetrics: &alertMetrics{},
	}

	_, _ = e.admitAlert()
	admitted, _ := e.admitAlert()
	assert.False(t, admitted)

	e.alertMetrics.Lock()
	e.alertMetrics.startTime = time.Now().Add(-2 * time.Minute)
	e.alertMetrics.Unlock()

	admitted, _ = e.admitAlert()
	assert.True(t, admitted, "a new window must admit alerts again")
}

// A limit of zero or less means no limit. The constructor replaces a zero with a
// default, so this guards the hand-built case only.
func TestAlertLimitZeroMeansNoLimit(t *testing.T) {
	e := &HTTPExporter{
		config:       HTTPExporterConfig{MaxAlertsPerMinute: 0},
		alertMetrics: &alertMetrics{},
	}
	for i := 0; i < 10; i++ {
		admitted, notify := e.admitAlert()
		assert.True(t, admitted, "alert %d must be admitted when there is no limit", i)
		assert.False(t, notify)
	}
}

// The decision is taken under one mutex, so concurrent senders must never admit
// more than the limit inside a window. Run with -race.
func TestAlertLimitUnderConcurrentSenders(t *testing.T) {
	const limit = 50
	e := &HTTPExporter{
		config:       HTTPExporterConfig{MaxAlertsPerMinute: limit},
		alertMetrics: &alertMetrics{},
	}

	var admitted, notified atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				ok, notify := e.admitAlert()
				if ok {
					admitted.Add(1)
				}
				if notify {
					notified.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(limit), admitted.Load(), "exactly the limit must be admitted")
	assert.Equal(t, int64(1), notified.Load(), "the notice must be decided once")
}
