package containerwatcher

import (
	"context"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
)

type ResultCallback func(utils.K8sEvent, string, uint32)

type ContainerWatcher interface {
	Ready() bool
	Start(ctx context.Context) error
	Stop()
	GetTracerCollection() *tracercollection.TracerCollection
	GetContainerCollection() *containercollection.ContainerCollection
	GetSocketEnricher() *socketenricher.SocketEnricher
	GetContainerSelector() *containercollection.ContainerSelector
	RegisterCustomTracer(tracer CustomTracer) error
	UnregisterCustomTracer(tracer CustomTracer) error
	RegisterContainerReceiver(receiver ContainerReceiver)
	UnregisterContainerReceiver(receiver ContainerReceiver)
}

type CustomTracer interface {
	Start() error
	Stop() error
	Name() string
}

type EventReceiver interface {
	ReportEvent(eventType utils.EventType, event utils.K8sEvent)
}

type EnrichedEventReceiver interface {
	ReportEnrichedEvent(enrichedEvent *events.EnrichedEvent)
}

type ContainerReceiver interface {
	ContainerCallback(notif containercollection.PubSubEvent)
}

type TaskBasedEnricher interface {
	SubmitEnrichmentTask(event utils.EnrichEvent, syscalls []uint64, callback ResultCallback, containerID string, processID uint32)
}
