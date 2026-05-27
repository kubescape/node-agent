package otelsetup

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const maxTrackedProfiles = 10_000

// ProfileLifecycleTracker manages one long-running trace span per container
// learning period. State transitions are recorded as span events.
type ProfileLifecycleTracker struct {
	spans      map[string]trace.Span
	ctxs       map[string]context.Context // span contexts, used to parent child spans
	counts     map[string]int             // checkpoint snapshot count per container (M2 throttle)
	startTimes map[string]time.Time
	mu         sync.Mutex
}

func NewProfileLifecycleTracker() *ProfileLifecycleTracker {
	return &ProfileLifecycleTracker{
		spans:      make(map[string]trace.Span),
		ctxs:       make(map[string]context.Context),
		counts:     make(map[string]int),
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
	spanCtx, span := Tracer().Start(context.Background(), "container.profile.learning",
		trace.WithAttributes(
			attribute.String("container.id", containerID),
			attribute.String("k8s.namespace.name", namespace),
			attribute.String("k8s.pod.name", pod),
			attribute.String("container.image.name", image),
		))
	t.spans[containerID] = span
	t.ctxs[containerID] = spanCtx
	t.counts[containerID] = 0
	t.startTimes[containerID] = time.Now()
}

// LearningSpanID returns the hex span ID of the active learning span for the
// given container, or an empty string if no span is tracked. Used by backend
// processors to link their own spans back into this trace.
func (t *ProfileLifecycleTracker) LearningSpanID(containerID string) string {
	t.mu.Lock()
	span, ok := t.spans[containerID]
	t.mu.Unlock()
	if !ok {
		return ""
	}
	sc := span.SpanContext()
	if !sc.IsValid() {
		return ""
	}
	return sc.SpanID().String()
}

// LearningTraceparent returns the W3C traceparent header value for the active
// learning span, or an empty string if no span is tracked. Stamp this onto
// storage objects so downstream components (kubescape/storage aggregation)
// can extract the remote span context and create properly parented child spans.
func (t *ProfileLifecycleTracker) LearningTraceparent(containerID string) string {
	t.mu.Lock()
	ctx, ok := t.ctxs[containerID]
	t.mu.Unlock()
	if !ok {
		return ""
	}
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	return carrier["traceparent"]
}

// LearningCtx returns the context carrying the active learning span for the
// given container, or context.Background() if no span is tracked. Pass this
// to logger.L().Ctx(...) at error sites so the log record inherits the
// learning span's trace_id/span_id for span↔log correlation.
func (t *ProfileLifecycleTracker) LearningCtx(containerID string) context.Context {
	t.mu.Lock()
	ctx, ok := t.ctxs[containerID]
	t.mu.Unlock()
	if !ok {
		return context.Background()
	}
	return ctx
}

// OnEntrySaved emits an immediate child span when a checkpoint profile is
// shipped, subject to M2 throttling: spans are emitted on the first snapshot,
// every 10th, and any snapshot that had dropped events. This keeps span
// volume within the per-agent budget while preserving visibility on errors.
func (t *ProfileLifecycleTracker) OnEntrySaved(containerID string, hasDropped bool) {
	t.mu.Lock()
	ctx, ok := t.ctxs[containerID]
	if !ok {
		t.mu.Unlock()
		return
	}
	t.counts[containerID]++
	count := t.counts[containerID]
	t.mu.Unlock()
	if count != 1 && count%10 != 0 && !hasDropped {
		return
	}
	_, child := Tracer().Start(ctx, "container.profile.cp.saved",
		trace.WithAttributes(
			attribute.String("container.id", containerID),
			attribute.Int("snapshot.number", count),
			attribute.Bool("has.dropped.events", hasDropped),
		),
	)
	child.End()
}

// OnLearningEnded ends the lifecycle span with the given reason
// ("completed", "evicted", "too_large", "terminated").
func (t *ProfileLifecycleTracker) OnLearningEnded(containerID, reason string) {
	t.mu.Lock()
	span, ok := t.spans[containerID]
	delete(t.spans, containerID)
	delete(t.ctxs, containerID)
	delete(t.counts, containerID)
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
	delete(t.ctxs, oldest)
	delete(t.counts, oldest)
	delete(t.startTimes, oldest)
}
