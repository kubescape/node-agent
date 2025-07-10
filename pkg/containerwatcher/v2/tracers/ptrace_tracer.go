package tracers

import (
	"context"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	tracerptrace "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer"
	tracerptracetype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

const ptraceTraceName = "trace_ptrace"

// PtraceTracer implements TracerInterface for ptrace events
type PtraceTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       func(utils.K8sEvent)
	tracer              *tracerptrace.Tracer
}

// NewPtraceTracer creates a new ptrace tracer
func NewPtraceTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback func(utils.K8sEvent),
) *PtraceTracer {
	return &PtraceTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
	}
}

// Start initializes and starts the ptrace tracer
func (pt *PtraceTracer) Start(ctx context.Context) error {
	if err := pt.tracerCollection.AddTracer(ptraceTraceName, pt.containerSelector); err != nil {
		return fmt.Errorf("adding ptrace tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	ptraceMountnsmap, err := pt.tracerCollection.TracerMountNsMap(ptraceTraceName)
	if err != nil {
		return fmt.Errorf("getting ptrace mountnsmap: %w", err)
	}

	tracerPtrace, err := tracerptrace.NewTracer(
		&tracerptrace.Config{MountnsMap: ptraceMountnsmap},
		pt.containerCollection,
		pt.ptraceEventCallback,
	)
	if err != nil {
		return fmt.Errorf("creating ptrace tracer: %w", err)
	}

	pt.tracer = tracerPtrace
	return nil
}

// Stop gracefully stops the ptrace tracer
func (pt *PtraceTracer) Stop() error {
	if pt.tracer != nil {
		pt.tracer.Close()
	}

	if err := pt.tracerCollection.RemoveTracer(ptraceTraceName); err != nil {
		return fmt.Errorf("removing ptrace tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (pt *PtraceTracer) GetName() string {
	return "ptrace_tracer"
}

// GetEventType returns the event type this tracer produces
func (pt *PtraceTracer) GetEventType() utils.EventType {
	return utils.PtraceEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (pt *PtraceTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		return config.EnableRuntimeDetection
	}
	return false
}

// ptraceEventCallback handles ptrace events from the tracer
func (pt *PtraceTracer) ptraceEventCallback(event *tracerptracetype.Event) {
	if event.Type != types.NORMAL {
		return
	}

	if pt.eventCallback != nil {
		pt.eventCallback(event)
	}
}
