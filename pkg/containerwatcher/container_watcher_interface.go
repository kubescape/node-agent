package containerwatcher

import (
	"context"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
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
	UnregisterCustomTracer(tracerName string) error
}

type CustomTracer interface {
	Start() error
	Stop() error
	Name() string
}
