package containerwatcher

import (
	"context"

	"github.com/kubescape/node-agent/pkg/utils"
)

// TracerManager manages all tracers in the container watcher
type TracerManager struct {
	tracers map[utils.EventType]TracerInterface
}

// NewTracerManager creates a new tracer manager
func NewTracerManager() *TracerManager {
	return &TracerManager{
		tracers: make(map[utils.EventType]TracerInterface),
	}
}

// RegisterTracer registers a tracer with the manager
func (tm *TracerManager) RegisterTracer(tracer TracerInterface) {
	tm.tracers[tracer.GetEventType()] = tracer
}

// GetTracer returns a tracer by event type
func (tm *TracerManager) GetTracer(eventType utils.EventType) (TracerInterface, bool) {
	tracer, exists := tm.tracers[eventType]
	return tracer, exists
}

// GetAllTracers returns all registered tracers
func (tm *TracerManager) GetAllTracers() map[utils.EventType]TracerInterface {
	return tm.tracers
}

// StartAllTracers starts all enabled tracers
func (tm *TracerManager) StartAllTracers(ctx context.Context, cfg interface{}) error {
	for _, tracer := range tm.tracers {
		if tracer.IsEnabled(cfg) {
			if err := tracer.Start(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

// StopAllTracers stops all tracers
func (tm *TracerManager) StopAllTracers() error {
	var lastErr error
	for _, tracer := range tm.tracers {
		if err := tracer.Stop(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
