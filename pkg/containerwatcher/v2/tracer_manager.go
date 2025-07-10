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
func NewV2TracerManager(containerWatcher *NewContainerWatcher) *V2TracerManager {
	return &V2TracerManager{
		containerWatcher: containerWatcher,
		tracerManager:    containerwatcherroot.NewTracerManager(),
	}
}

// SetTracerFactory sets the tracer factory
func (vtm *V2TracerManager) SetTracerFactory(factory containerwatcherroot.TracerFactoryInterface) {
	vtm.tracerFactory = factory
}

// StartAllTracers starts all enabled tracers
func (vtm *V2TracerManager) StartAllTracers(ctx context.Context) error {
	// Create and register all tracers
	if vtm.tracerFactory != nil {
		vtm.tracerFactory.CreateAllTracers(vtm.tracerManager)
	}

	// Start all enabled tracers
	return vtm.tracerManager.StartAllTracers(ctx, vtm.containerWatcher.cfg)
}

// StopAllTracers stops all tracers
func (vtm *V2TracerManager) StopAllTracers() error {
	return vtm.tracerManager.StopAllTracers()
}
