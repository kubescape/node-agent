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

	tracerhardlink "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/tracer"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

const hardlinkTraceName = "trace_hardlink"

var _ containerwatcher.TracerInterface = (*HardlinkTracer)(nil)

// HardlinkTracer implements TracerInterface for hardlink events
type HardlinkTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       containerwatcher.ResultCallback
	tracer              *tracerhardlink.Tracer
	thirdPartyEnricher  containerwatcher.TaskBasedEnricher
}

// NewHardlinkTracer creates a new hardlink tracer
func NewHardlinkTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *HardlinkTracer {
	return &HardlinkTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
		thirdPartyEnricher:  thirdPartyEnricher,
	}
}

// Start initializes and starts the hardlink tracer
func (ht *HardlinkTracer) Start(ctx context.Context) error {
	if err := ht.tracerCollection.AddTracer(hardlinkTraceName, ht.containerSelector); err != nil {
		return fmt.Errorf("adding hardlink tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	hardlinkMountnsmap, err := ht.tracerCollection.TracerMountNsMap(hardlinkTraceName)
	if err != nil {
		return fmt.Errorf("getting hardlink mountnsmap: %w", err)
	}

	tracerHardlink, err := tracerhardlink.NewTracer(
		&tracerhardlink.Config{MountnsMap: hardlinkMountnsmap},
		ht.containerCollection,
		ht.hardlinkEventCallback,
	)
	if err != nil {
		return fmt.Errorf("creating hardlink tracer: %w", err)
	}

	ht.tracer = tracerHardlink
	return nil
}

// Stop gracefully stops the hardlink tracer
func (ht *HardlinkTracer) Stop() error {
	if ht.tracer != nil {
		ht.tracer.Stop()
	}

	if err := ht.tracerCollection.RemoveTracer(hardlinkTraceName); err != nil {
		return fmt.Errorf("removing hardlink tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (ht *HardlinkTracer) GetName() string {
	return "hardlink_tracer"
}

// GetEventType returns the event type this tracer produces
func (ht *HardlinkTracer) GetEventType() utils.EventType {
	return utils.HardlinkEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (ht *HardlinkTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		return !config.DHardlink && config.EnableRuntimeDetection
	}
	return false
}

// hardlinkEventCallback handles hardlink events from the tracer
func (ht *HardlinkTracer) hardlinkEventCallback(event *tracerhardlinktype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Warning("hardlink tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	// Handle the event with syscall enrichment
	ht.handleEvent(event, []uint64{SYS_LINK, SYS_LINKAT})
}

// handleEvent processes the event with syscall enrichment
func (ht *HardlinkTracer) handleEvent(event *tracerhardlinktype.Event, syscalls []uint64) {
	if ht.eventCallback != nil {
		// Extract container ID and process ID from the hardlink event
		containerID := event.Runtime.ContainerID
		processID := event.Pid

		EnrichEvent(ht.thirdPartyEnricher, event, syscalls, ht.eventCallback, containerID, processID)
	}
}
