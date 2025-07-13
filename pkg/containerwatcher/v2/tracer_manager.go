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

	// Start procfs tracer 5 seconds before other tracers
	var procfsTracer containerwatcherroot.TracerInterface
	if tracer, exists := vtm.tracerManager.GetTracer(utils.ProcfsEventType); exists {
		procfsTracer = tracer
		// Remove procfs tracer from manager temporarily to avoid double-starting
		delete(vtm.tracerManager.GetAllTracers(), utils.ProcfsEventType)

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
