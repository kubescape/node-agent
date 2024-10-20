package containerwatcher

import (
	"context"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/node-agent/pkg/utils"
)

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

type ContainerReceiver interface {
	ContainerCallback(notif containercollection.PubSubEvent)
}

type ThirdPartyEnricher interface {
	Enrich(eventType utils.EventType, event utils.K8sEvent) error
}
