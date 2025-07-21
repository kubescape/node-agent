package containerwatcher

import (
	"context"
	"fmt"
	"time"

	"github.com/kubescape/go-logger"
	containerwatcherroot "github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

// V2TracerManager handles all tracer-related operations for v2
type V2TracerManager struct {
	containerWatcher *ContainerWatcher
	tracers          map[utils.EventType]containerwatcherroot.TracerInterface
	tracerFactory    containerwatcherroot.TracerFactoryInterface
}

// NewV2TracerManager creates a new v2 tracer manager
func NewV2TracerManager(containerWatcher *ContainerWatcher, tracerFactory containerwatcherroot.TracerFactoryInterface) *V2TracerManager {
	return &V2TracerManager{
		containerWatcher: containerWatcher,
		tracers:          make(map[utils.EventType]containerwatcherroot.TracerInterface),
		tracerFactory:    tracerFactory,
	}
}

// RegisterTracer registers a tracer with the manager
func (vtm *V2TracerManager) RegisterTracer(tracer containerwatcherroot.TracerInterface) {
	vtm.tracers[tracer.GetEventType()] = tracer
}

// GetTracer returns a tracer by event type
func (vtm *V2TracerManager) GetTracer(eventType utils.EventType) (containerwatcherroot.TracerInterface, bool) {
	tracer, exists := vtm.tracers[eventType]
	return tracer, exists
}

// GetAllTracers returns all registered tracers
func (vtm *V2TracerManager) GetAllTracers() map[utils.EventType]containerwatcherroot.TracerInterface {
	return vtm.tracers
}

// StartAllTracers starts all enabled tracers
func (vtm *V2TracerManager) StartAllTracers(ctx context.Context) error {
	// Create and register all tracers
	if vtm.tracerFactory != nil {
		vtm.tracerFactory.CreateAllTracers(vtm)
	}

	// Start procfs tracer 5 seconds before other tracers
	var procfsTracer containerwatcherroot.TracerInterface
	if tracer, exists := vtm.GetTracer(utils.ProcfsEventType); exists {
		procfsTracer = tracer
		// Remove procfs tracer from manager temporarily to avoid double-starting
		delete(vtm.tracers, utils.ProcfsEventType)

		if procfsTracer.IsEnabled(vtm.containerWatcher.cfg) {
			logger.L().Info("Starting procfs tracer 5 seconds before other tracers")
			if err := procfsTracer.Start(ctx); err != nil {
				return fmt.Errorf("starting procfs tracer: %w", err)
			}
		}
	}

	// Wait 5 seconds before starting other tracers
	select {
	case <-time.After(5 * time.Second):
		// Continue with other tracers
	case <-ctx.Done():
		return ctx.Err()
	}

	// Start all other enabled tracers
	for _, tracer := range vtm.tracers {
		if tracer.IsEnabled(vtm.containerWatcher.cfg) {
			if err := tracer.Start(ctx); err != nil {
				return err
			}
		}
	}

	// Start third-party tracers through the factory
	if factory, ok := vtm.tracerFactory.(interface {
		StartThirdPartyTracers(context.Context) error
	}); ok {
		if err := factory.StartThirdPartyTracers(ctx); err != nil {
			return err
		}
	}

	return nil
}

// StopAllTracers stops all tracers
func (vtm *V2TracerManager) StopAllTracers() error {
	// Stop third-party tracers through the factory
	if factory, ok := vtm.tracerFactory.(interface {
		StopThirdPartyTracers()
	}); ok {
		factory.StopThirdPartyTracers()
	}

	// Stop all registered tracers
	var lastErr error
	for _, tracer := range vtm.tracers {
		if err := tracer.Stop(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
