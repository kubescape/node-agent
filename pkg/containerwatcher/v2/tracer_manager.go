package containerwatcher

import (
	"context"
	"fmt"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/config"
	containerwatcherroot "github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

type TracerManager struct {
	cfg           config.Config
	tracers       map[utils.EventType]containerwatcherroot.TracerInterface
	tracerFactory containerwatcherroot.TracerFactoryInterface
}

func NewTracerManager(cfg config.Config, tracerFactory containerwatcherroot.TracerFactoryInterface) *TracerManager {
	return &TracerManager{
		cfg:           cfg,
		tracers:       make(map[utils.EventType]containerwatcherroot.TracerInterface),
		tracerFactory: tracerFactory,
	}
}

func (vtm *TracerManager) RegisterTracer(tracer containerwatcherroot.TracerInterface) {
	vtm.tracers[tracer.GetEventType()] = tracer
}

func (vtm *TracerManager) GetTracer(eventType utils.EventType) (containerwatcherroot.TracerInterface, bool) {
	tracer, exists := vtm.tracers[eventType]
	return tracer, exists
}

func (vtm *TracerManager) GetAllTracers() map[utils.EventType]containerwatcherroot.TracerInterface {
	return vtm.tracers
}

func (vtm *TracerManager) StartAllTracers(ctx context.Context) error {
	vtm.tracerFactory.CreateAllTracers(vtm)

	if err := vtm.startProcfsTracer(ctx); err != nil {
		return err
	}

	for _, tracer := range vtm.tracers {
		if tracer.IsEnabled(vtm.cfg) {
			if err := tracer.Start(ctx); err != nil {
				return err
			}
		}
	}

	if err := vtm.tracerFactory.StartThirdPartyTracers(ctx); err != nil {
		return err
	}

	return nil
}

func (vtm *TracerManager) StopAllTracers() error {
	vtm.tracerFactory.StopThirdPartyTracers()

	var lastErr error
	for _, tracer := range vtm.tracers {
		if err := tracer.Stop(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (vtm *TracerManager) startProcfsTracer(ctx context.Context) error {
	var procfsTracer containerwatcherroot.TracerInterface
	if tracer, exists := vtm.GetTracer(utils.ProcfsEventType); exists {
		procfsTracer = tracer
		delete(vtm.tracers, utils.ProcfsEventType)

		if procfsTracer.IsEnabled(vtm.cfg) {
			logger.L().Info("Starting procfs tracer 5 seconds before other tracers")
			if err := procfsTracer.Start(ctx); err != nil {
				return fmt.Errorf("starting procfs tracer: %w", err)
			}
		}
	}

	select {
	case <-time.After(5 * time.Second):
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}
