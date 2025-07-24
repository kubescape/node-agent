package containerwatcher

import (
	"context"
	"fmt"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

type TracerManager struct {
	cfg               config.Config
	tracers           map[utils.EventType]containerwatcher.TracerInterface
	tracerFactory     containerwatcher.TracerFactoryInterface
	thirdPartyTracers []containerwatcher.CustomTracer
}

func NewTracerManager(cfg config.Config, tracerFactory containerwatcher.TracerFactoryInterface) *TracerManager {
	return &TracerManager{
		cfg:               cfg,
		tracers:           make(map[utils.EventType]containerwatcher.TracerInterface),
		tracerFactory:     tracerFactory,
		thirdPartyTracers: make([]containerwatcher.CustomTracer, 0),
	}
}

func (tm *TracerManager) RegisterTracer(tracer containerwatcher.TracerInterface) {
	tm.tracers[tracer.GetEventType()] = tracer
}

func (tm *TracerManager) GetTracer(eventType utils.EventType) (containerwatcher.TracerInterface, bool) {
	tracer, exists := tm.tracers[eventType]
	return tracer, exists
}

func (tm *TracerManager) GetAllTracers() map[utils.EventType]containerwatcher.TracerInterface {
	return tm.tracers
}

func (tm *TracerManager) StartAllTracers(ctx context.Context) error {
	tm.tracerFactory.CreateAllTracers(tm)

	if err := tm.startProcfsTracer(ctx); err != nil {
		return err
	}

	for _, tracer := range tm.tracers {
		if tracer.IsEnabled(tm.cfg) {
			if err := tracer.Start(ctx); err != nil {
				return err
			}
			logger.L().Info("Started tracer", helpers.String("tracer", tracer.GetName()))
		}
	}

	tm.thirdPartyTracers = tm.tracerFactory.GetThirdPartyTracers()
	if err := tm.startThirdPartyTracers(); err != nil {
		return err
	}

	return nil
}

func (tm *TracerManager) StopAllTracers() error {
	tm.stopThirdPartyTracers()

	var lastErr error
	for _, tracer := range tm.tracers {
		if err := tracer.Stop(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (tm *TracerManager) startProcfsTracer(ctx context.Context) error {
	if tracer, exists := tm.GetTracer(utils.ProcfsEventType); exists {
		delete(tm.tracers, utils.ProcfsEventType)
		if tracer.IsEnabled(tm.cfg) {
			logger.L().Info("Starting procfs tracer 5 seconds before other tracers")
			if err := tracer.Start(ctx); err != nil {
				return fmt.Errorf("starting procfs tracer: %w", err)
			}
		}
	}

	select {
	case <-time.After(tm.cfg.ProcfsScanInterval):
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

// startThirdPartyTracers starts all registered third-party tracers
func (tm *TracerManager) startThirdPartyTracers() error {
	for _, tracer := range tm.thirdPartyTracers {
		if err := tracer.Start(); err != nil {
			logger.L().Error("error starting custom tracer", helpers.String("tracer", tracer.Name()), helpers.Error(err))
			return fmt.Errorf("starting custom tracer %s: %w", tracer.Name(), err)
		}
		logger.L().Info("started custom tracer", helpers.String("tracer", tracer.Name()))
	}
	return nil
}

// stopThirdPartyTracers stops all registered third-party tracers
func (tm *TracerManager) stopThirdPartyTracers() {
	for _, tracer := range tm.thirdPartyTracers {
		if err := tracer.Stop(); err != nil {
			logger.L().Error("error stopping custom tracer", helpers.String("tracer", tracer.Name()), helpers.Error(err))
		}
	}
}
