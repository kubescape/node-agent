package tracers

import (
	"context"
	"fmt"
	"strings"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercapabilities "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/tracer"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/utils"
)

const capabilitiesTraceName = "trace_capabilities"

// CapabilitiesTracer implements TracerInterface for capabilities events
type CapabilitiesTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       func(utils.K8sEvent)
	tracer              *tracercapabilities.Tracer
}

// NewCapabilitiesTracer creates a new capabilities tracer
func NewCapabilitiesTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback func(utils.K8sEvent),
) *CapabilitiesTracer {
	return &CapabilitiesTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
	}
}

// Start initializes and starts the capabilities tracer
func (ct *CapabilitiesTracer) Start(ctx context.Context) error {
	if err := ct.tracerCollection.AddTracer(capabilitiesTraceName, ct.containerSelector); err != nil {
		return fmt.Errorf("adding capabilities tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	capabilitiesMountnsmap, err := ct.tracerCollection.TracerMountNsMap(capabilitiesTraceName)
	if err != nil {
		return fmt.Errorf("getting capabilities mountnsmap: %w", err)
	}

	tracerCapabilities, err := tracercapabilities.NewTracer(
		&tracercapabilities.Config{MountnsMap: capabilitiesMountnsmap},
		ct.containerCollection,
		ct.capabilitiesEventCallback,
	)
	if err != nil {
		return fmt.Errorf("creating capabilities tracer: %w", err)
	}

	ct.tracer = tracerCapabilities
	return nil
}

// Stop gracefully stops the capabilities tracer
func (ct *CapabilitiesTracer) Stop() error {
	if ct.tracer != nil {
		ct.tracer.Stop()
	}

	if err := ct.tracerCollection.RemoveTracer(capabilitiesTraceName); err != nil {
		return fmt.Errorf("removing capabilities tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (ct *CapabilitiesTracer) GetName() string {
	return "capabilities_tracer"
}

// GetEventType returns the event type this tracer produces
func (ct *CapabilitiesTracer) GetEventType() utils.EventType {
	return utils.CapabilitiesEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ct *CapabilitiesTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		return config.EnableRuntimeDetection
	}
	return false
}

// capabilitiesEventCallback handles capabilities events from the tracer
func (ct *CapabilitiesTracer) capabilitiesEventCallback(event *tracercapabilitiestype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		// Log dropped events but don't process them
		return
	}

	if ct.eventCallback != nil {
		ct.eventCallback(event)
	}
}

// isDroppedEvent checks if an event should be dropped
func isDroppedEvent(eventType types.EventType, message string) bool {
	return eventType != types.NORMAL &&
		eventType != types.DEBUG &&
		strings.Contains(message, "stop tracing container")
}
