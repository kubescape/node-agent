package containerwatcher

import (
	"context"

	containerwatcherroot "github.com/kubescape/node-agent/pkg/containerwatcher"
)

// V2TracerManager handles all tracer-related operations for v2
type V2TracerManager struct {
	containerWatcher *NewContainerWatcher
	tracerManager    *containerwatcherroot.TracerManager
	tracerFactory    containerwatcherroot.TracerFactoryInterface
}

// NewV2TracerManager creates a new v2 tracer manager
func NewV2TracerManager(containerWatcher *NewContainerWatcher, tracerFactory containerwatcherroot.TracerFactoryInterface) *V2TracerManager {
	return &V2TracerManager{
		containerWatcher: containerWatcher,
		tracerManager:    containerwatcherroot.NewTracerManager(),
		tracerFactory:    tracerFactory,
	}
}

// StartAllTracers starts all enabled tracers
func (vtm *V2TracerManager) StartAllTracers(ctx context.Context) error {
	// Create and register all tracers
	if vtm.tracerFactory != nil {
		vtm.tracerFactory.CreateAllTracers(vtm.tracerManager)
	}

	// Start all enabled tracers
	if err := vtm.tracerManager.StartAllTracers(ctx, vtm.containerWatcher.cfg); err != nil {
		return err
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

	return vtm.tracerManager.StopAllTracers()
}
