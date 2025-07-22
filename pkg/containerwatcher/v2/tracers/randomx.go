package tracers

import (
	"context"
	"fmt"
	"runtime"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	tracerandomx "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/tracer"
	tracerandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

const randomxTraceName = "trace_randomx"

var _ containerwatcher.TracerInterface = (*RandomXTracer)(nil)

// RandomXTracer implements TracerInterface for RandomX events
type RandomXTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       func(utils.K8sEvent, string, uint32)
	tracer              *tracerandomx.Tracer
}

// NewRandomXTracer creates a new RandomX tracer
func NewRandomXTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback func(utils.K8sEvent, string, uint32),
) *RandomXTracer {
	return &RandomXTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
	}
}

// Start initializes and starts the RandomX tracer
func (rt *RandomXTracer) Start(ctx context.Context) error {
	// RandomX tracing is only supported on amd64 architecture
	if runtime.GOARCH != "amd64" {
		logger.L().Warning("randomx tracing is not supported on this architecture", helpers.String("architecture", runtime.GOARCH))
		return nil
	}

	if err := rt.tracerCollection.AddTracer(randomxTraceName, rt.containerSelector); err != nil {
		return fmt.Errorf("adding randomx tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	randomxMountnsmap, err := rt.tracerCollection.TracerMountNsMap(randomxTraceName)
	if err != nil {
		return fmt.Errorf("getting randomx mountnsmap: %w", err)
	}

	tracerRandomx, err := tracerandomx.NewTracer(
		&tracerandomx.Config{MountnsMap: randomxMountnsmap},
		rt.containerCollection,
		rt.randomxEventCallback,
	)
	if err != nil {
		return fmt.Errorf("creating randomx tracer: %w", err)
	}

	rt.tracer = tracerRandomx
	return nil
}

// Stop gracefully stops the RandomX tracer
func (rt *RandomXTracer) Stop() error {
	if rt.tracer != nil {
		rt.tracer.Stop()
	}

	if err := rt.tracerCollection.RemoveTracer(randomxTraceName); err != nil {
		return fmt.Errorf("removing randomx tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (rt *RandomXTracer) GetName() string {
	return "randomx_tracer"
}

// GetEventType returns the event type this tracer produces
func (rt *RandomXTracer) GetEventType() utils.EventType {
	return utils.RandomXEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (rt *RandomXTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		return config.EnableRuntimeDetection && runtime.GOARCH == "amd64"
	}
	return false
}

// randomxEventCallback handles RandomX events from the tracer
func (rt *RandomXTracer) randomxEventCallback(event *tracerandomxtype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Warning("randomx tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	if rt.eventCallback != nil {
		// Extract container ID and process ID from the RandomX event
		containerID := event.Runtime.ContainerID
		processID := event.Pid

		rt.eventCallback(event, containerID, processID)
	}
}
