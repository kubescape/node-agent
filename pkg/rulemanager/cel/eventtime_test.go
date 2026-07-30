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
func execEventAt(ts int64) *utils.StructEvent {
	return &utils.StructEvent{
		EventType: utils.ExecveEventType,
		Comm:      "curl",
		Timestamp: ts,
	}
}

func TestResolveEventTime_PrefersEventTimestamp(t *testing.T) {
	kernelTime := time.Date(2026, 7, 28, 12, 0, 3, 100000000, time.UTC)
	observed := kernelTime.Add(5 * time.Millisecond)

	ee := &events.EnrichedEvent{
		Event:     execEventAt(kernelTime.UnixNano()),
		Timestamp: observed,
	}
	assert.Equal(t, kernelTime.UTC(), ResolveEventTime(ee).UTC(),
		"kernel time must win over observation time")
}

func TestResolveEventTime_FallsBackWhenEventTimestampIsZero(t *testing.T) {
	observed := time.Date(2026, 7, 28, 12, 0, 3, 0, time.UTC)
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

	kernelTime := time.Date(2026, 7, 28, 12, 0, 3, 100000000, time.UTC)
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

	kernelTime := time.Date(2026, 7, 28, 12, 0, 3, 0, time.UTC)
	ee := &events.EnrichedEvent{
		Event:     execEventAt(kernelTime.UnixNano()),
		Timestamp: kernelTime,
	}

	out, err := c.EvaluateExpression(ee,
		`string(timestamp - duration("1m") < timestamp)`)
	require.NoError(t, err)
	assert.Equal(t, "true", out)
}
