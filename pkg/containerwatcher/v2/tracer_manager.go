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

// TracerManager manages the lifecycle of all eBPF and custom tracers
//
// Responsibilities:
// - Register and coordinate ~20 different tracers (exec, network, dns, http, etc.)
// - Stagger tracer startup to prevent concurrent eBPF loading (reduces peak RSS from 1.4GB to 500MB)
// - Handle graceful shutdown of all tracers
//
// Key implementation detail: Tracers spawn goroutines in Start() for eBPF loading.
// Without controlled startup, all tracers load concurrently, causing kernel memory pressure.
type TracerManager struct {
	cfg               config.Config
	tracers           map[utils.EventType]containerwatcher.TracerInterface
	tracerFactory     containerwatcher.TracerFactoryInterface
	thirdPartyTracers []containerwatcher.TracerInterface
}

func NewTracerManager(cfg config.Config, tracerFactory containerwatcher.TracerFactoryInterface) *TracerManager {
	return &TracerManager{
		cfg:               cfg,
		tracers:           make(map[utils.EventType]containerwatcher.TracerInterface),
		tracerFactory:     tracerFactory,
		thirdPartyTracers: make([]containerwatcher.TracerInterface, 0),
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

// StartAllTracers initializes and starts all tracers with staggered startup
//
// Memory optimization strategy:
// Tracers load eBPF programs into kernel space via Inspektor Gadget. Without delays,
// all ~20 tracers call runtime.RunGadget() in a tight loop, causing concurrent
// bpf() syscalls. This results in peak RSS of ~1.4GB (kernel allocates separate
// regions for each tracer's eBPF programs/maps).
//
// Adding delays between tracers allows sequential eBPF loading, reducing peak to
// ~500MB. The delay enables kernel to share BTF data and establish shared maps
// before the next tracer loads. Go heap memory remains unaffected (~100-180MB).
//
// Delay value must exceed eBPF initialization time (~250-500ms per tracer).
// Current value of 2s ensures no overlap; 1s would also work per testing.
// 0ms or time.After(0) provides no benefit (equivalent to tight loop).
func (tm *TracerManager) StartAllTracers(ctx context.Context) error {
	tm.tracerFactory.CreateAllTracers(tm)

	if err := tm.startProcfsTracer(ctx); err != nil {
		return err
	}

	tracerCount := 0
	for _, tracer := range tm.tracers {
		if !tracer.IsEnabled(tm.cfg) {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Start tracer and continue on error instead of failing entire startup.
			// This keeps partial tracer availability even if some tracers fail to initialize.
			// Combined with staggered delays, this prevents cascading failures from overwhelming the system.
			if err := tracer.Start(ctx); err != nil {
				logger.L().Error("error starting tracer", helpers.String("tracer", tracer.GetName()), helpers.Error(err))
				continue
			}
			tracerCount++
			logger.L().Info("Started tracer", helpers.String("tracer", tracer.GetName()), helpers.Int("count", tracerCount))
		}

		// Wait before starting next tracer to prevent concurrent eBPF loading

		// Memory reduction mechanism:
		// Each tracer.Start() spawns a goroutine that calls runtime.RunGadget(),
		// which loads eBPF programs into kernel space via bpf() syscalls.
		// Concurrent loading causes kernel to allocate separate memory regions
		// for each tracer's eBPF programs and maps, leading to ~1.4GB peak RSS.
		//
		// Sequential loading allows kernel to:
		// 1. Share BTF (BPF Type Format) data between eBPF programs
		// 2. Establish shared maps (socket enrichment, kube metadata) once
		// 3. Avoid memory fragmentation from concurrent bpf() syscalls
		//
		// Note: Delay value must exceed eBPF load time (~250-500ms per tracer).
		// Values of 1s, 2s, and 5s all achieve same memory profile (~500MB peak).
		// The key is preventing overlap, not the exact delay duration.
		// Go heap remains stable (~100-180MB); reduction is in kernel eBPF memory.
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
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

// startProcfsTracer starts the procfs tracer ahead of eBPF tracers
//
// The procfs tracer scans /proc for container/process information and needs
// time to initialize before other tracers (which may depend on this data).
// This prevents potential race conditions where eBPF tracers attempt to
// enrich process info before procfs has completed its initial scan.
func (tm *TracerManager) startProcfsTracer(ctx context.Context) error {
	if tracer, exists := tm.GetTracer(utils.ProcfsEventType); exists {
		delete(tm.tracers, utils.ProcfsEventType)
		if tracer.IsEnabled(tm.cfg) {
			logger.L().Info("Starting procfs tracer before other tracers")
			if err := tracer.Start(ctx); err != nil {
				return fmt.Errorf("starting procfs tracer: %w", err)
			}
		}
	}

	// Wait for procfs scan to complete before starting eBPF tracers.
	// This delay ensures container/process data is ready for enrichment.
	select {
	case <-time.After(tm.cfg.ProcfsScanInterval):
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

// stopThirdPartyTracers stops all registered third-party tracers
func (tm *TracerManager) stopThirdPartyTracers() {
	for _, tracer := range tm.thirdPartyTracers {
		if err := tracer.Stop(); err != nil {
			logger.L().Error("error stopping custom tracer", helpers.String("tracer", tracer.GetName()), helpers.Error(err))
		}
	}
}
