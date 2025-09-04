package tracers

import (
	"context"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	tracerexit "github.com/kubescape/node-agent/pkg/ebpf/gadgets/exit/tracer"
	tracerexittype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/exit/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

const exitTraceName = "trace_exit"

var _ containerwatcher.TracerInterface = (*ExitTracer)(nil)

// ExitTracer implements TracerInterface for exit events
type ExitTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       containerwatcher.ResultCallback
	tracer              *tracerexit.Tracer
}

// NewExitTracer creates a new exit tracer
func NewExitTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback containerwatcher.ResultCallback,
) *ExitTracer {
	return &ExitTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
	}
}

// Start initializes and starts the exit tracer
func (et *ExitTracer) Start(ctx context.Context) error {
	if err := et.tracerCollection.AddTracer(exitTraceName, et.containerSelector); err != nil {
		return fmt.Errorf("adding exit tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	exitMountnsmap, err := et.tracerCollection.TracerMountNsMap(exitTraceName)
	if err != nil {
		return fmt.Errorf("getting exit mountnsmap: %w", err)
	}

	tracerExit, err := tracerexit.NewTracer(
		&tracerexit.Config{MountnsMap: exitMountnsmap},
		et.containerCollection,
		et.exitEventCallback,
	)
	if err != nil {
		return fmt.Errorf("creating exit tracer: %w", err)
	}

	et.tracer = tracerExit
	return nil
}

// Stop gracefully stops the exit tracer
func (et *ExitTracer) Stop() error {
	if et.tracer != nil {
		et.tracer.Stop()
	}

	if err := et.tracerCollection.RemoveTracer(exitTraceName); err != nil {
		return fmt.Errorf("removing exit tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (et *ExitTracer) GetName() string {
	return "exit_tracer"
}

// GetEventType returns the event type this tracer produces
func (et *ExitTracer) GetEventType() utils.EventType {
	return utils.ExitEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (et *ExitTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		if config.DExit {
			return false
		}
		return config.EnableRuntimeDetection || config.EnableApplicationProfile
	}
	return false
}

// exitEventCallback handles exit events from the tracer
func (et *ExitTracer) exitEventCallback(event *tracerexittype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if et.eventCallback != nil {
		// Extract container ID and process ID from the exit event
		containerID := event.Runtime.ContainerID
		processID := event.Pid

		et.eventCallback(event, containerID, processID)
	}
}
