package hostwatcher

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/node-agent/pkg/utils"
)

type HostWatcher interface {
	Ready() bool
	Start(ctx context.Context) error
	Stop()
	GetTracerCollection() *tracercollection.TracerCollection
	GetSocketEnricher() *socketenricher.SocketEnricher
	RegisterCustomTracer(tracer CustomTracer) error
	UnregisterCustomTracer(tracer CustomTracer) error
}

type CustomTracer interface {
	Start() error
	Stop() error
	Name() string
}

type EventReceiver interface {
	ReportEvent(eventType utils.EventType, event utils.K8sEvent)
}

type ThirdPartyEnricher interface {
	Enrich(event utils.EnrichEvent, syscall []uint64)
}
