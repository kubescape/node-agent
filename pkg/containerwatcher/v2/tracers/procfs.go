package tracers

import (
	"context"
	"fmt"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerexittype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/exit/types"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	procfsTraceName = "trace_procfs"
)

var _ containerwatcher.TracerInterface = (*ProcfsTracer)(nil)

// ProcfsTracer implements TracerInterface for procfs events
type ProcfsTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	procfsEventCallback func(utils.K8sEvent, string, uint32)
	exitEventCallback   func(utils.K8sEvent, string, uint32)
	procfsFeeder        *feeder.ProcfsFeeder
	started             bool
}

// NewProcfsTracer creates a new procfs tracer
func NewProcfsTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	procfsEventCallback func(utils.K8sEvent, string, uint32),
	exitEventCallback containerwatcher.ResultCallback,
	cfg config.Config,
	processTreeManager processtree.ProcessTreeManager,
) *ProcfsTracer {
	return &ProcfsTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		procfsEventCallback: procfsEventCallback,
		exitEventCallback:   exitEventCallback,
		procfsFeeder:        feeder.NewProcfsFeeder(cfg.ProcfsScanInterval, cfg.ProcfsPidScanInterval, processTreeManager),
	}
}

// Start initializes and starts the procfs tracer
func (pt *ProcfsTracer) Start(ctx context.Context) error {
	if pt.started {
		return fmt.Errorf("procfs tracer already started")
	}

	// Start the procfs feeder
	if err := pt.procfsFeeder.Start(ctx); err != nil {
		return fmt.Errorf("starting procfs feeder: %w", err)
	}

	// Subscribe to procfs events
	eventChan := make(chan conversion.ProcessEvent, 1000)
	pt.procfsFeeder.Subscribe(eventChan)

	// Start event processing goroutine
	go pt.processEvents(ctx, eventChan)

	pt.started = true
	logger.L().Info("ProcfsTracer started successfully")
	return nil
}

// Stop gracefully stops the procfs tracer
func (pt *ProcfsTracer) Stop() error {
	if !pt.started {
		return nil
	}

	if pt.procfsFeeder != nil {
		if err := pt.procfsFeeder.Stop(); err != nil {
			logger.L().Error("error stopping procfs feeder", helpers.Error(err))
		}
	}

	pt.started = false
	logger.L().Info("ProcfsTracer stopped successfully")
	return nil
}

// GetName returns the unique name of the tracer
func (pt *ProcfsTracer) GetName() string {
	return "procfs_tracer"
}

// GetEventType returns the event type this tracer produces
func (pt *ProcfsTracer) GetEventType() utils.EventType {
	return utils.ProcfsEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (pt *ProcfsTracer) IsEnabled(cfg config.Config) bool {
	return cfg.EnableRuntimeDetection
}

// processEvents processes events from the procfs feeder
func (pt *ProcfsTracer) processEvents(ctx context.Context, eventChan <-chan conversion.ProcessEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-eventChan:
			switch event.Type {
			case conversion.ExitEvent:
				pt.handleExitEvent(event)
			case conversion.ProcfsEvent:
				pt.handleProcfsEvent(event)
			default:
				logger.L().Error("unknown event type", helpers.Int("eventType", int(event.Type)))
			}
		}
	}
}

func (pt *ProcfsTracer) handleExitEvent(event conversion.ProcessEvent) {
	exitEvent := &tracerexittype.Event{
		Pid:  event.PID,
		PPid: event.PPID,
		Comm: "exit",
	}

	exitEvent.Event.Timestamp = types.Time(event.Timestamp.UnixNano())

	pt.exitEventCallback(exitEvent, event.ContainerID, event.PID)
}

// handleProcfsEvent handles a single procfs event
func (pt *ProcfsTracer) handleProcfsEvent(event conversion.ProcessEvent) {
	// Create a procfs event that can be processed by the ordered event queue
	// Use current time as event timestamp, not the process timestamp
	procfsEvent := &events.ProcfsEvent{
		Type:        types.NORMAL,
		Timestamp:   types.Time(time.Now().UnixNano()),
		PID:         event.PID,
		PPID:        event.PPID,
		Comm:        event.Comm,
		Pcomm:       event.Pcomm,
		Cmdline:     event.Cmdline,
		Uid:         event.Uid,
		Gid:         event.Gid,
		Cwd:         event.Cwd,
		Path:        event.Path,
		StartTimeNs: event.StartTimeNs,
		ContainerID: event.ContainerID,
		HostPID:     event.HostPID,
		HostPPID:    event.HostPPID,
	}

	// Extract container ID and process ID for the callback
	containerID := event.ContainerID
	if containerID == "" {
		// If no container ID is available, use a placeholder
		containerID = "host"
	}
	processID := event.PID

	// Send to the ordered event queue
	if pt.procfsEventCallback != nil {
		pt.procfsEventCallback(procfsEvent, containerID, processID)
	}
}
