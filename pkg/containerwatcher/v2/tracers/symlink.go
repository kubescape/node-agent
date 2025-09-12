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

	tracersymlink "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/tracer"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

const symlinkTraceName = "trace_symlink"

var _ containerwatcher.TracerInterface = (*SymlinkTracer)(nil)

// SymlinkTracer implements TracerInterface for symlink events
type SymlinkTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       containerwatcher.ResultCallback
	tracer              *tracersymlink.Tracer
	thirdPartyEnricher  containerwatcher.TaskBasedEnricher
}

// NewSymlinkTracer creates a new symlink tracer
func NewSymlinkTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback containerwatcher.ResultCallback,
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *SymlinkTracer {
	return &SymlinkTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
		thirdPartyEnricher:  thirdPartyEnricher,
	}
}

// Start initializes and starts the symlink tracer
func (st *SymlinkTracer) Start(ctx context.Context) error {
	if err := st.tracerCollection.AddTracer(symlinkTraceName, st.containerSelector); err != nil {
		return fmt.Errorf("adding symlink tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	symlinkMountnsmap, err := st.tracerCollection.TracerMountNsMap(symlinkTraceName)
	if err != nil {
		return fmt.Errorf("getting symlink mountnsmap: %w", err)
	}

	tracerSymlink, err := tracersymlink.NewTracer(
		&tracersymlink.Config{MountnsMap: symlinkMountnsmap},
		//st.containerCollection,
		st.symlinkEventCallback,
	)
	if err != nil {
		return fmt.Errorf("creating symlink tracer: %w", err)
	}

	st.tracer = tracerSymlink
	return nil
}

// Stop gracefully stops the symlink tracer
func (st *SymlinkTracer) Stop() error {
	if st.tracer != nil {
		st.tracer.Stop()
	}

	if err := st.tracerCollection.RemoveTracer(symlinkTraceName); err != nil {
		return fmt.Errorf("removing symlink tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (st *SymlinkTracer) GetName() string {
	return "symlink_tracer"
}

// GetEventType returns the event type this tracer produces
func (st *SymlinkTracer) GetEventType() utils.EventType {
	return utils.SymlinkEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (st *SymlinkTracer) IsEnabled(cfg config.Config) bool {
	return !cfg.DSymlink && cfg.EnableRuntimeDetection
}

// symlinkEventCallback handles symlink events from the tracer
func (st *SymlinkTracer) symlinkEventCallback(event *tracersymlinktype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Warning("symlink tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	// Handle the event with syscall enrichment
	st.handleEvent(event, []uint64{SYS_SYMLINK, SYS_SYMLINKAT})
}

// handleEvent processes the event with syscall enrichment
func (st *SymlinkTracer) handleEvent(event *tracersymlinktype.Event, syscalls []uint64) {
	if st.eventCallback != nil {
		// Extract container ID and process ID from the symlink event
		containerID := event.Runtime.ContainerID
		processID := event.Pid

		EnrichEvent(st.thirdPartyEnricher, event, syscalls, st.eventCallback, containerID, processID)
	}
}
