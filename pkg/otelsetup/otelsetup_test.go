package otelsetup

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdklog "go.opentelemetry.io/otel/sdk/log"
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

// --- isARMOEndpoint (AC8/AC9) ---

func TestIsARMOEndpoint_ExactMatch(t *testing.T) {
	t.Setenv("ARMO_OTEL_AUTH", "")
	assert.True(t, isARMOEndpoint("otel.armosec.io:4317"), "exact ARMO host should match")
}

func TestIsARMOEndpoint_SubdomainNotMatched(t *testing.T) {
	t.Setenv("ARMO_OTEL_AUTH", "")
	assert.False(t, isARMOEndpoint("evil.otel.armosec.io:4317"), "subdomain must not match")
}

func TestIsARMOEndpoint_CustomerCollector(t *testing.T) {
	t.Setenv("ARMO_OTEL_AUTH", "")
	assert.False(t, isARMOEndpoint("customer-collector:4317"), "non-ARMO host must not match")
}

func TestIsARMOEndpoint_EmptyEndpoint(t *testing.T) {
	t.Setenv("ARMO_OTEL_AUTH", "")
	assert.False(t, isARMOEndpoint(""), "empty endpoint must not match")
}

func TestIsARMOEndpoint_ForceAuthEnvVar(t *testing.T) {
	t.Setenv("ARMO_OTEL_AUTH", "true")
	assert.True(t, isARMOEndpoint("customer-collector:4317"), "ARMO_OTEL_AUTH=true forces match")
}

func TestIsARMOEndpoint_WithScheme(t *testing.T) {
	t.Setenv("ARMO_OTEL_AUTH", "")
	assert.True(t, isARMOEndpoint("https://otel.armosec.io:4317"), "endpoint with https scheme")
}

// --- ProfileLifecycleTracker (AC4) ---

func TestProfileLifecycleTracker_StartEndCompleted(t *testing.T) {
	rec, cleanup := newTestTracerProvider(t)
	defer cleanup()

	tracker := NewProfileLifecycleTracker()
	tracker.OnLearningStarted("cid-1", "ns", "pod", "img:latest")
	tracker.OnEntrySaved("cid-1")
	tracker.OnEntrySaved("cid-1")
	tracker.OnLearningEnded("cid-1", "completed")

	spans := rec.Ended()
	require.Len(t, spans, 1, "expected exactly one span")

	span := spans[0]
	assert.Equal(t, "container.profile.learning", span.Name())

	// Verify span attributes
	attrs := make(map[string]string)
	for _, a := range span.Attributes() {
		attrs[string(a.Key)] = a.Value.AsString()
	}
	assert.Equal(t, "cid-1", attrs["container.id"])
	assert.Equal(t, "ns", attrs["k8s.namespace.name"])
	assert.Equal(t, "pod", attrs["k8s.pod.name"])
	assert.Equal(t, "img:latest", attrs["container.image.name"])

	// Verify span events: 2× profile.entry.saved + 1× learning.completed
	events := span.Events()
	require.Len(t, events, 3, "expected 2 entry-saved events + 1 learning.completed")
	assert.Equal(t, "profile.entry.saved", events[0].Name)
	assert.Equal(t, "profile.entry.saved", events[1].Name)
	assert.Equal(t, "learning.completed", events[2].Name)
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
	// Call End without Start — must not panic
	assert.NotPanics(t, func() {
		tracker.OnLearningEnded("nonexistent", "completed")
	})
	assert.Empty(t, rec.Ended(), "no spans should be emitted for unknown container")
}

func TestProfileLifecycleTracker_CapEviction(t *testing.T) {
	rec, cleanup := newTestTracerProvider(t)
	defer cleanup()

	// Fill the tracker beyond cap using a temp maxTrackedProfiles value.
	// We inject 2 containers, then set a synthetic cap by calling evictOldest directly.
	tracker := NewProfileLifecycleTracker()
	tracker.OnLearningStarted("old", "ns", "pod", "")
	time.Sleep(time.Millisecond) // ensure old < new in startTimes
	tracker.OnLearningStarted("new", "ns", "pod", "")

	// Directly test evictOldest
	tracker.mu.Lock()
	tracker.evictOldest()
	tracker.mu.Unlock()

	// "old" should have been evicted and its span ended
	spans := rec.Ended()
	require.Len(t, spans, 1)
	events := spans[0].Events()
	require.Len(t, events, 1)
	assert.Equal(t, "learning.evicted_cap_exceeded", events[0].Name)

	// "new" should still be tracked
	tracker.mu.Lock()
	_, newExists := tracker.spans["new"]
	_, oldExists := tracker.spans["old"]
	tracker.mu.Unlock()
	assert.True(t, newExists, "new container should remain tracked")
	assert.False(t, oldExists, "old container should be evicted")
}

// --- SlowEvalThreshold ---

func TestSlowEvalThreshold_Default(t *testing.T) {
	// Before InitProviders is called the threshold should be 0 (uninitialized).
	// After a simulated init it should reflect the configured value.
	slowEvalThresholdNs.Store(5 * int64(time.Millisecond))
	assert.Equal(t, 5*time.Millisecond, SlowEvalThreshold())
}

// --- RingBufferLogProcessor ---

func TestRingBufferLogProcessor_WrapsCorrectly(t *testing.T) {
	p := &RingBufferLogProcessor{}
	// Fill beyond capacity and verify size stays bounded.
	ctx := context.Background()
	r := new(sdklog.Record)
	for range len(p.buf) + 100 {
		_ = p.OnEmit(ctx, r)
	}
	p.mu.Lock()
	sz := p.size
	p.mu.Unlock()
	assert.Equal(t, len(p.buf), sz, "buffer size must be capped at ring capacity")
}
