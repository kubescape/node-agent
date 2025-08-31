package tracers

import (
	"context"
	"fmt"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	toptracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/tracer"
	toptypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	topTraceName = "trace_top"
	maxRows      = 1000
)

var _ containerwatcher.TracerInterface = (*TopTracer)(nil)

// TopTracer implements TracerInterface for top events (Prometheus metrics)
type TopTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       containerwatcher.ResultCallback
	tracer              *toptracer.Tracer
}

// NewTopTracer creates a new top tracer
func NewTopTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback containerwatcher.ResultCallback,
) *TopTracer {
	return &TopTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
	}
}

// Start initializes and starts the top tracer
func (tt *TopTracer) Start(ctx context.Context) error {
	if err := tt.tracerCollection.AddTracer(topTraceName, tt.containerSelector); err != nil {
		return fmt.Errorf("adding top tracer: %w", err)
	}

	topTracer, err := toptracer.NewTracer(
		&toptracer.Config{Interval: time.Minute, MaxRows: maxRows},
		tt.containerCollection,
		tt.topEventCallback,
	)
	if err != nil {
		return fmt.Errorf("creating top tracer: %w", err)
	}

	tt.tracer = topTracer
	return nil
}

// Stop gracefully stops the top tracer
func (tt *TopTracer) Stop() error {
	if tt.tracer != nil {
		tt.tracer.Stop()
	}

	if err := tt.tracerCollection.RemoveTracer(topTraceName); err != nil {
		return fmt.Errorf("removing top tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (tt *TopTracer) GetName() string {
	return "top_tracer"
}

// GetEventType returns the event type this tracer produces
func (tt *TopTracer) GetEventType() utils.EventType {
	return utils.AllEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (tt *TopTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		return !config.DTop && config.EnablePrometheusExporter
	}
	return false
}

// topEventCallback handles top events from the tracer
func (tt *TopTracer) topEventCallback(event *top.Event[toptypes.Stats]) {
	if event.Error != "" {
		// Top events are not K8sEvents, so we need to handle them differently
		// For now, we'll skip them in the unified approach
		// TODO: Implement proper top event handling
		return
	}

	// Top events are not K8sEvents, so we need to handle them differently
	// For now, we'll skip them in the unified approach
	// TODO: Implement proper top event handling
	_ = event
}
