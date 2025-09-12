package tracers

import (
	"context"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	traceriouring "github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer"
	traceriouringtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

const iouringTraceName = "trace_iouring"

var _ containerwatcher.TracerInterface = (*IoUringTracer)(nil)

// IoUringTracer implements TracerInterface for io_uring events
type IoUringTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       containerwatcher.ResultCallback
	tracer              *traceriouring.Tracer
}

// NewIoUringTracer creates a new io_uring tracer
func NewIoUringTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback containerwatcher.ResultCallback,
) *IoUringTracer {
	return &IoUringTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
	}
}

// Start initializes and starts the io_uring tracer
func (it *IoUringTracer) Start(_ context.Context) error {
	if err := it.tracerCollection.AddTracer(iouringTraceName, it.containerSelector); err != nil {
		return fmt.Errorf("adding io_uring tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	iouringMountnsmap, err := it.tracerCollection.TracerMountNsMap(iouringTraceName)
	if err != nil {
		return fmt.Errorf("getting io_uring mountnsmap: %w", err)
	}

	tracerIouring, err := traceriouring.NewTracer(
		&traceriouring.Config{MountnsMap: iouringMountnsmap},
		//it.containerCollection,
		it.iouringEventCallback,
	)
	if err != nil {
		logger.L().Warning("Failed to create io_uring tracer", helpers.Error(err))
		return nil
	}

	it.tracer = tracerIouring
	return nil
}

// Stop gracefully stops the io_uring tracer
func (it *IoUringTracer) Stop() error {
	if it.tracer != nil {
		it.tracer.Stop()
	}

	if err := it.tracerCollection.RemoveTracer(iouringTraceName); err != nil {
		return fmt.Errorf("removing io_uring tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (it *IoUringTracer) GetName() string {
	return "iouring_tracer"
}

// GetEventType returns the event type this tracer produces
func (it *IoUringTracer) GetEventType() utils.EventType {
	return utils.IoUringEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (it *IoUringTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DIouring && cfg.EnableRuntimeDetection
}

// iouringEventCallback handles io_uring events from the tracer
func (it *IoUringTracer) iouringEventCallback(event *traceriouringtype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Warning("io_uring tracer got drop events - we may miss some realtime data",
			helpers.Interface("event", event),
			helpers.String("error", event.Message))
		return
	}

	if it.eventCallback != nil {
		// Extract container ID and process ID from the IoUring event
		containerID := event.Runtime.ContainerID
		processID := event.Pid

		it.eventCallback(event, containerID, processID)
	}
}
