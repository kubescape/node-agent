package tracers

import (
	"context"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	containerwatcherv1 "github.com/kubescape/node-agent/pkg/containerwatcher/v1"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
)

const execTraceName = "trace_exec"

// ExecTracer implements TracerInterface for exec events
type ExecTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       func(utils.K8sEvent)
	tracer              *tracerexec.Tracer
}

// NewExecTracer creates a new exec tracer
func NewExecTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback func(utils.K8sEvent),
) *ExecTracer {
	return &ExecTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
	}
}

// Start initializes and starts the exec tracer
func (et *ExecTracer) Start(ctx context.Context) error {
	if err := et.tracerCollection.AddTracer(execTraceName, et.containerSelector); err != nil {
		return fmt.Errorf("adding exec tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	execMountnsmap, err := et.tracerCollection.TracerMountNsMap(execTraceName)
	if err != nil {
		return fmt.Errorf("getting exec mountnsmap: %w", err)
	}

	tracerExec, err := tracerexec.NewTracer(
		&tracerexec.Config{MountnsMap: execMountnsmap, GetPaths: true},
		et.containerCollection,
		et.execEventCallback,
	)
	if err != nil {
		return fmt.Errorf("creating exec tracer: %w", err)
	}

	et.tracer = tracerExec
	return nil
}

// Stop gracefully stops the exec tracer
func (et *ExecTracer) Stop() error {
	if et.tracer != nil {
		et.tracer.Stop()
	}

	if err := et.tracerCollection.RemoveTracer(execTraceName); err != nil {
		return fmt.Errorf("removing exec tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (et *ExecTracer) GetName() string {
	return "exec_tracer"
}

// GetEventType returns the event type this tracer produces
func (et *ExecTracer) GetEventType() utils.EventType {
	return utils.ExecveEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (et *ExecTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		return config.EnableApplicationProfile || config.EnableRuntimeDetection
	}
	return false
}

// execEventCallback handles exec events from the tracer
func (et *ExecTracer) execEventCallback(event *tracerexectype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if event.Retval > -1 && event.Comm != "" {
		execEvent := &events.ExecEvent{Event: *event}
		// Handle the event with syscall enrichment
		et.handleEvent(execEvent, []uint64{containerwatcherv1.SYS_FORK})
	}
}

// handleEvent processes the event with syscall enrichment
func (et *ExecTracer) handleEvent(event *events.ExecEvent, syscalls []uint64) {
	// TODO: Implement syscall enrichment logic
	// For now, just pass the event to the callback
	if et.eventCallback != nil {
		et.eventCallback(event)
	}
}
