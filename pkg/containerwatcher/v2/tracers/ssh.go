package tracers

import (
	"context"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	tracerssh "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/tracer"
	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

const sshTraceName = "trace_ssh"

var _ containerwatcher.TracerInterface = (*SSHTracer)(nil)

// SSHTracer implements TracerInterface for SSH events
type SSHTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       containerwatcher.ResultCallback
	tracer              *tracerssh.Tracer
	socketEnricher      *socketenricher.SocketEnricher
}

// NewSSHTracer creates a new SSH tracer
func NewSSHTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback containerwatcher.ResultCallback,
	socketEnricher *socketenricher.SocketEnricher,
) *SSHTracer {
	return &SSHTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
		socketEnricher:      socketEnricher,
	}
}

// Start initializes and starts the SSH tracer
func (st *SSHTracer) Start(ctx context.Context) error {
	if err := st.tracerCollection.AddTracer(sshTraceName, st.containerSelector); err != nil {
		return fmt.Errorf("adding SSH tracer: %w", err)
	}

	tracerSsh, err := tracerssh.NewTracer()
	if err != nil {
		return fmt.Errorf("creating SSH tracer: %w", err)
	}

	if st.socketEnricher != nil {
		tracerSsh.SetSocketEnricherMap(st.socketEnricher.SocketsMap())
	} else {
		logger.L().Error("SSHTracer - socket enricher is nil")
	}

	tracerSsh.SetEventHandler(st.sshEventCallback)

	err = tracerSsh.RunWorkaround()
	if err != nil {
		return fmt.Errorf("running workaround: %w", err)
	}

	st.tracer = tracerSsh

	config := &networktracer.ConnectToContainerCollectionConfig[tracersshtype.Event]{
		Tracer:   st.tracer,
		Resolver: st.containerCollection,
		Selector: st.containerSelector,
		Base:     tracersshtype.Base,
	}

	_, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		return fmt.Errorf("connecting tracer to container collection: %w", err)
	}

	return nil
}

// Stop gracefully stops the SSH tracer
func (st *SSHTracer) Stop() error {
	if st.tracer != nil {
		st.tracer.Close()
	}

	if err := st.tracerCollection.RemoveTracer(sshTraceName); err != nil {
		return fmt.Errorf("removing SSH tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (st *SSHTracer) GetName() string {
	return "ssh_tracer"
}

// GetEventType returns the event type this tracer produces
func (st *SSHTracer) GetEventType() utils.EventType {
	return utils.SSHEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (st *SSHTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		return !config.DSsh && config.EnableRuntimeDetection
	}
	return false
}

// sshEventCallback handles SSH events from the tracer
func (st *SSHTracer) sshEventCallback(event *tracersshtype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Warning("ssh tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	st.containerCollection.EnrichByMntNs(&event.CommonData, event.MountNsID)
	st.containerCollection.EnrichByNetNs(&event.CommonData, event.NetNsID)

	if st.eventCallback != nil {
		// Extract container ID and process ID from the SSH event
		containerID := event.Runtime.ContainerID
		processID := event.Pid

		st.eventCallback(event, containerID, processID)
	}
}
