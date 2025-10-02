package tracers

import (
	"context"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	tracerfork "github.com/kubescape/node-agent/pkg/ebpf/gadgets/fork/tracer"
	tracerforktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/fork/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

const forkTraceName = "trace_fork"

var _ containerwatcher.TracerInterface = (*ForkTracer)(nil)

// ForkTracer implements TracerInterface for fork events
type ForkTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       containerwatcher.ResultCallback
	tracer              *tracerfork.Tracer
}

// NewForkTracer creates a new fork tracer
func NewForkTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback containerwatcher.ResultCallback,
) *ForkTracer {
	return &ForkTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
	}
}

// Start initializes and starts the fork tracer
func (ft *ForkTracer) Start(ctx context.Context) error {
	if err := ft.tracerCollection.AddTracer(forkTraceName, ft.containerSelector); err != nil {
		return fmt.Errorf("adding fork tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	forkMountnsmap, err := ft.tracerCollection.TracerMountNsMap(forkTraceName)
	if err != nil {
		return fmt.Errorf("getting fork mountnsmap: %w", err)
	}

	tracerFork, err := tracerfork.NewTracer(
		&tracerfork.Config{MountnsMap: forkMountnsmap},
		//ft.containerCollection,
		ft.forkEventCallback,
	)
	if err != nil {
		return fmt.Errorf("creating fork tracer: %w", err)
	}

	ft.tracer = tracerFork
	return nil
}

// Stop gracefully stops the fork tracer
func (ft *ForkTracer) Stop() error {
	if ft.tracer != nil {
		ft.tracer.Stop()
	}

	if err := ft.tracerCollection.RemoveTracer(forkTraceName); err != nil {
		return fmt.Errorf("removing fork tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (ft *ForkTracer) GetName() string {
	return "fork_tracer"
}

// GetEventType returns the event type this tracer produces
func (ft *ForkTracer) GetEventType() utils.EventType {
	return utils.ForkEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ft *ForkTracer) IsEnabled(cfg config.Config) bool {
	if cfg.DFork {
		return false
	}
	return cfg.EnableApplicationProfile || cfg.EnableRuntimeDetection
}

// forkEventCallback handles fork events from the tracer
func (ft *ForkTracer) forkEventCallback(event *tracerforktype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if ft.eventCallback != nil {
		// Extract container ID and process ID from the fork event
		containerID := event.Runtime.ContainerID
		processID := event.Pid

		ft.eventCallback(event, containerID, processID)
	}
}
