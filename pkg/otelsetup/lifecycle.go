package otelsetup

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const maxTrackedProfiles = 10_000

// ProfileLifecycleTracker manages one long-running trace span per container
// learning period. State transitions are recorded as span events.
type ProfileLifecycleTracker struct {
	spans      map[string]trace.Span
	startTimes map[string]time.Time
	mu         sync.Mutex
}

func NewProfileLifecycleTracker() *ProfileLifecycleTracker {
	return &ProfileLifecycleTracker{
		spans:      make(map[string]trace.Span),
		startTimes: make(map[string]time.Time),
	}
}

// OnLearningStarted begins a lifecycle span for the container.
func (t *ProfileLifecycleTracker) OnLearningStarted(containerID, namespace, pod, image string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.spans) >= maxTrackedProfiles {
		t.evictOldest()
	}
	if existing, ok := t.spans[containerID]; ok {
		existing.AddEvent("learning.replaced")
		existing.End()
	}
	ctx := context.Background()
	_, span := Tracer().Start(ctx, "container.profile.learning",
		trace.WithAttributes(
			attribute.String("container.id", containerID),
			attribute.String("k8s.namespace.name", namespace),
			attribute.String("k8s.pod.name", pod),
			attribute.String("container.image.name", image),
		))
	t.spans[containerID] = span
	t.startTimes[containerID] = time.Now()
}

// OnEntrySaved records a span event for profile data added during learning.
func (t *ProfileLifecycleTracker) OnEntrySaved(containerID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if span, ok := t.spans[containerID]; ok {
		span.AddEvent("profile.entry.saved")
	}
}

// OnLearningEnded ends the lifecycle span with the given reason
// ("completed", "evicted", "too_large", "terminated").
func (t *ProfileLifecycleTracker) OnLearningEnded(containerID, reason string) {
	t.mu.Lock()
	span, ok := t.spans[containerID]
	delete(t.spans, containerID)
	delete(t.startTimes, containerID)
	t.mu.Unlock()
	if ok {
		span.AddEvent("learning." + reason)
		span.End()
	}
}

// evictOldest force-ends the span with the earliest start time. Must be called with mu held.
func (t *ProfileLifecycleTracker) evictOldest() {
	if len(t.spans) == 0 {
		return
	}
	var oldest string
	var oldestTime time.Time
	first := true
	for id, ts := range t.startTimes {
		if first || ts.Before(oldestTime) {
			oldest, oldestTime = id, ts
			first = false
		}
	}
	if span, ok := t.spans[oldest]; ok {
		span.AddEvent("learning.evicted_cap_exceeded")
		span.End()
	}
	delete(t.spans, oldest)
	delete(t.startTimes, oldest)
}
