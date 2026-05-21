package otelsetup

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// newTestTracerProvider installs an in-memory tracer provider and returns the
// span recorder and a cleanup func that restores the global provider.
func newTestTracerProvider(t *testing.T) (*tracetest.SpanRecorder, func()) {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	return rec, func() { otel.SetTracerProvider(prev) }
}

// --- SlowEvalThreshold ---

func TestSlowEvalThreshold_Default(t *testing.T) {
	prev := slowEvalThresholdNs.Load()
	t.Cleanup(func() { slowEvalThresholdNs.Store(prev) })
	slowEvalThresholdNs.Store(5 * int64(time.Millisecond))
	assert.Equal(t, 5*time.Millisecond, SlowEvalThreshold())
}

// --- ProfileLifecycleTracker ---

func TestProfileLifecycleTracker_StartEndCompleted(t *testing.T) {
	rec, cleanup := newTestTracerProvider(t)
	defer cleanup()

	tracker := NewProfileLifecycleTracker()
	tracker.OnLearningStarted("cid-1", "ns", "pod", "img:latest")
	tracker.OnEntrySaved("cid-1", false) // count=1: emitted (first)
	tracker.OnEntrySaved("cid-1", false) // count=2: suppressed by M2 throttle
	tracker.OnLearningEnded("cid-1", "completed")

	// 1 child CP span (only the first; second is throttled) + 1 parent learning span
	spans := rec.Ended()
	require.Len(t, spans, 2, "expected 1 cp.saved child span (M2 throttled) + 1 parent learning span")

	assert.Equal(t, "container.profile.cp.saved", spans[0].Name())

	// Verify snapshot.number attribute on the child
	childAttrs := make(map[string]interface{})
	for _, a := range spans[0].Attributes() {
		childAttrs[string(a.Key)] = a.Value.AsInterface()
	}
	assert.Equal(t, "cid-1", childAttrs["container.id"])
	assert.Equal(t, int64(1), childAttrs["snapshot.number"])

	// Last span is the parent
	parent := spans[1]
	assert.Equal(t, "container.profile.learning", parent.Name())

	// Parent has the container attributes
	attrs := make(map[string]string)
	for _, a := range parent.Attributes() {
		attrs[string(a.Key)] = a.Value.AsString()
	}
	assert.Equal(t, "cid-1", attrs["container.id"])
	assert.Equal(t, "ns", attrs["k8s.namespace.name"])
	assert.Equal(t, "pod", attrs["k8s.pod.name"])
	assert.Equal(t, "img:latest", attrs["container.image.name"])

	// Parent has only the terminal event
	events := parent.Events()
	require.Len(t, events, 1, "expected only learning.completed on parent")
	assert.Equal(t, "learning.completed", events[0].Name)

	// Child span is parented under the learning span
	parentSpanID := parent.SpanContext().SpanID()
	assert.Equal(t, parentSpanID, spans[0].Parent().SpanID())
}

func TestProfileLifecycleTracker_Terminated(t *testing.T) {
	rec, cleanup := newTestTracerProvider(t)
	defer cleanup()

	tracker := NewProfileLifecycleTracker()
	tracker.OnLearningStarted("cid-2", "ns", "pod", "")
	tracker.OnLearningEnded("cid-2", "terminated")

	spans := rec.Ended()
	require.Len(t, spans, 1)
	events := spans[0].Events()
	require.Len(t, events, 1)
	assert.Equal(t, "learning.terminated", events[0].Name)
}

func TestProfileLifecycleTracker_EndWithoutStart(t *testing.T) {
	rec, cleanup := newTestTracerProvider(t)
	defer cleanup()

	tracker := NewProfileLifecycleTracker()
	assert.NotPanics(t, func() {
		tracker.OnLearningEnded("nonexistent", "completed")
	})
	assert.Empty(t, rec.Ended(), "no spans should be emitted for unknown container")
}

func TestProfileLifecycleTracker_CapEviction(t *testing.T) {
	rec, cleanup := newTestTracerProvider(t)
	defer cleanup()

	tracker := NewProfileLifecycleTracker()
	tracker.OnLearningStarted("old", "ns", "pod", "")
	time.Sleep(time.Millisecond)
	tracker.OnLearningStarted("new", "ns", "pod", "")

	tracker.mu.Lock()
	tracker.evictOldest()
	tracker.mu.Unlock()

	spans := rec.Ended()
	require.Len(t, spans, 1)
	events := spans[0].Events()
	require.Len(t, events, 1)
	assert.Equal(t, "learning.evicted_cap_exceeded", events[0].Name)

	tracker.mu.Lock()
	_, newExists := tracker.spans["new"]
	_, oldExists := tracker.spans["old"]
	tracker.mu.Unlock()
	assert.True(t, newExists)
	assert.False(t, oldExists)
}
