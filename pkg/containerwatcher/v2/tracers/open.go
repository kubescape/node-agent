package tracers

import (
	"context"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
)

const openTraceName = "trace_open"

var _ containerwatcher.TracerInterface = (*OpenTracer)(nil)

// OpenTracer implements TracerInterface for open events
type OpenTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       func(utils.K8sEvent, string, uint32)
	tracer              *traceropen.Tracer
	cfg                 config.Config
	pathResolver        *PathResolver
	thirdPartyEnricher  containerwatcher.TaskBasedEnricher
}

// NewOpenTracer creates a new open tracer
func NewOpenTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback func(utils.K8sEvent, string, uint32),
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *OpenTracer {
	pathResolver := NewPathResolver()
	return &OpenTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
		thirdPartyEnricher:  thirdPartyEnricher,
		pathResolver:        pathResolver,
	}
}

// Start initializes and starts the open tracer
func (ot *OpenTracer) Start(ctx context.Context) error {
	if err := ot.tracerCollection.AddTracer(openTraceName, ot.containerSelector); err != nil {
		return fmt.Errorf("adding open tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	openMountnsmap, err := ot.tracerCollection.TracerMountNsMap(openTraceName)
	if err != nil {
		return fmt.Errorf("getting open mountnsmap: %w", err)
	}

	tracerOpen, err := traceropen.NewTracer(
		&traceropen.Config{MountnsMap: openMountnsmap, FullPath: true},
		ot.containerCollection,
		ot.openEventCallback,
	)
	if err != nil {
		return fmt.Errorf("creating open tracer: %w", err)
	}

	ot.tracer = tracerOpen
	return nil
}

// Stop gracefully stops the open tracer
func (ot *OpenTracer) Stop() error {
	if ot.tracer != nil {
		ot.tracer.Stop()
	}

	if err := ot.tracerCollection.RemoveTracer(openTraceName); err != nil {
		return fmt.Errorf("removing open tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (ot *OpenTracer) GetName() string {
	return "open_tracer"
}

// GetEventType returns the event type this tracer produces
func (ot *OpenTracer) GetEventType() utils.EventType {
	return utils.OpenEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ot *OpenTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		ot.cfg = config
		return config.EnableApplicationProfile || config.EnableRuntimeDetection
	}
	return false
}

// openEventCallback handles open events from the tracer
func (ot *OpenTracer) openEventCallback(event *traceropentype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if ot.cfg.EnableFullPathTracing {
		event.Path = event.FullPath
	}

	if !ot.cfg.EnableFullPathTracing {
		fullPath, err := ot.pathResolver.ResolvePath(event.Pid, event.Path)
		if err != nil {
			event.FullPath = event.Path
		} else {
			event.FullPath = fullPath
			event.Path = fullPath
		}
	}

	if event.K8s.ContainerName == "" {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		return
	}

	if event.Err > -1 && event.FullPath != "" {
		openEvent := &events.OpenEvent{Event: *event}
		// Handle the event with syscall enrichment
		ot.handleEvent(openEvent, []uint64{SYS_OPEN, SYS_OPENAT})
	}
}

// handleEvent processes the event with syscall enrichment
func (ot *OpenTracer) handleEvent(event *events.OpenEvent, syscalls []uint64) {
	if ot.eventCallback != nil {
		containerID := event.Runtime.ContainerID
		processID := event.Pid

		EnrichEvent(ot.thirdPartyEnricher, event, syscalls, ot.eventCallback, containerID, processID)
	}
}
