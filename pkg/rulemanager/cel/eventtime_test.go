package cel

import (
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// execEventAt builds an exec event whose kernel timestamp is ts.
//
// A real utils.StructEvent is used rather than a hand-rolled fake: the eval
// context casts the event to utils.CelEvent and calls GetEventType() on it, so a
// fake embedding a nil utils.K8sEvent panics before reaching the assertion.
// recentTime is a wall-clock instant close to now, truncated so equality
// assertions stay exact.
//
// Fixed calendar dates were used here originally, and they are wrong for this
// function: ResolveEventTime now rejects a timestamp implausibly far from now, so
// a hard-coded date silently becomes an "implausible epoch" the moment it ages
// past the bound. Real events always carry a near-now wall clock; the fixtures
// must too.
func recentTime() time.Time {
	return time.Now().Add(-time.Second).Truncate(time.Millisecond)
}

func execEventAt(ts int64) *utils.StructEvent {
	return &utils.StructEvent{
		EventType: utils.ExecveEventType,
		Comm:      "curl",
		Timestamp: ts,
	}
}

func TestResolveEventTime_PrefersEventTimestamp(t *testing.T) {
	kernelTime := recentTime()
	observed := kernelTime.Add(5 * time.Millisecond)

	ee := &events.EnrichedEvent{
		Event:     execEventAt(kernelTime.UnixNano()),
		Timestamp: observed,
	}
	assert.Equal(t, kernelTime.UTC(), ResolveEventTime(ee).UTC(),
		"kernel time must win over observation time")
}

func TestResolveEventTime_FallsBackWhenEventTimestampIsZero(t *testing.T) {
	observed := recentTime()
	ee := &events.EnrichedEvent{
		Event:     execEventAt(0),
		Timestamp: observed,
	}
	assert.Equal(t, observed.UTC(), ResolveEventTime(ee).UTC(),
		"a zero event timestamp must fall back, not yield the epoch")
}

func TestResolveEventTime_NilSafe(t *testing.T) {
	assert.True(t, ResolveEventTime(nil).IsZero())
	assert.True(t, ResolveEventTime(&events.EnrichedEvent{}).IsZero(),
		"a nil inner event must not panic on the hot path")
}

func TestEvalContext_TimestampIsUsableFromCEL(t *testing.T) {
	c := newTestCEL(t)

	kernelTime := recentTime()
	ee := &events.EnrichedEvent{
		Event:     execEventAt(kernelTime.UnixNano()),
		Timestamp: kernelTime,
	}

	out, err := c.EvaluateExpression(ee, `string(timestamp)`)
	require.NoError(t, err)

	// CEL renders a timestamp in the location Go gives it, and time.Unix builds
	// a local-zone Time -- so the rendered offset depends on the node's TZ.
	// Assert the instant, not the spelling, or this test fails everywhere except
	// a UTC machine.
	got, err := time.Parse(time.RFC3339Nano, out)
	require.NoError(t, err, "timestamp must render as RFC3339: %q", out)
	assert.True(t, kernelTime.Equal(got), "want %s, got %s", kernelTime, got)
}

// The whole point of the variable: comparing a remembered time against the
// current event's time. If timestamp were not a CEL timestamp this would not
// compile, and every _ts ordering guard would silently be dead.
func TestEvalContext_TimestampSupportsOrderingComparisons(t *testing.T) {
	c := newTestCEL(t)

	kernelTime := recentTime()
	ee := &events.EnrichedEvent{
		Event:     execEventAt(kernelTime.UnixNano()),
		Timestamp: kernelTime,
	}

	out, err := c.EvaluateExpression(ee,
		`string(timestamp - duration("1m") < timestamp)`)
	require.NoError(t, err)
	assert.Equal(t, "true", out)
}

// A producer that ever hands over a raw boot-time value instead of a wall clock
// would yield 1970-plus-uptime. ExpiresAt is derived from the event clock while
// expiry is checked against time.Now(), so every entry from that stream would be
// born expired and the rule would silently never fire -- the failure mode this
// feature works hardest elsewhere to design out. No producer does this today; the
// bound is here so that staying true is not a matter of luck.
func TestResolveEventTime_RejectsAnImplausibleEpoch(t *testing.T) {
	enrichmentTime := time.Now().Add(-2 * time.Second)

	bootTimeNs := (37 * time.Hour).Nanoseconds() // ~1.5 days of uptime, in 1970
	ee := &events.EnrichedEvent{
		Event:     &utils.StructEvent{EventType: utils.ExecveEventType, Timestamp: bootTimeNs},
		Timestamp: enrichmentTime,
	}
	assert.Equal(t, enrichmentTime, ResolveEventTime(ee),
		"a boot-time value must fall back to the enrichment time, not resolve to 1970")

	// A far-future reading is equally implausible and equally damaging: the entry
	// would never expire.
	future := time.Now().Add(72 * time.Hour)
	ee.Event = &utils.StructEvent{EventType: utils.ExecveEventType, Timestamp: future.UnixNano()}
	assert.Equal(t, enrichmentTime, ResolveEventTime(ee))
}

// The bound must not reject real events. It is there to catch a wrong epoch, not
// clock skew, so anything within a day either way is kept.
func TestResolveEventTime_KeepsLateAndSlightlyAheadEvents(t *testing.T) {
	for _, offset := range []time.Duration{
		-23 * time.Hour, -time.Minute, -time.Millisecond, 0, time.Second, 23 * time.Hour,
	} {
		want := time.Now().Add(offset)
		ee := &events.EnrichedEvent{
			Event:     &utils.StructEvent{EventType: utils.ExecveEventType, Timestamp: want.UnixNano()},
			Timestamp: time.Now(),
		}
		assert.WithinDuration(t, want, ResolveEventTime(ee), time.Microsecond,
			"an event %s from now is legitimate and must keep its own timestamp", offset)
	}
}
