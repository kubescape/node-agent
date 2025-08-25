package containerwatcher

import (
	"context"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
)

type ContainerWatcherMock struct{}

func (c ContainerWatcherMock) Ready() bool {
	return true
}

func (c ContainerWatcherMock) Start(_ context.Context) error {
	return nil
}

func (c ContainerWatcherMock) Stop() {}

func (c ContainerWatcherMock) RegisterCustomTracer(_ TracerInterface) error {
	return nil
}

func (c ContainerWatcherMock) UnregisterCustomTracer(_ TracerInterface) error {
	return nil
}

func (c ContainerWatcherMock) RegisterContainerReceiver(_ ContainerReceiver) {}

func (c ContainerWatcherMock) UnregisterContainerReceiver(_ ContainerReceiver) {}

func (c ContainerWatcherMock) GetTracerCollection() *tracercollection.TracerCollection {
	return nil
}

func (c ContainerWatcherMock) GetContainerCollection() *containercollection.ContainerCollection {
	return nil
}

func (c ContainerWatcherMock) GetSocketEnricher() *socketenricher.SocketEnricher {
	return nil
}

func (c ContainerWatcherMock) GetContainerSelector() *containercollection.ContainerSelector {
	return nil
}

var _ ContainerWatcher = (*ContainerWatcherMock)(nil)

type CustomTracerMock struct{}

func (c CustomTracerMock) Start() error {
	return nil
}

func (c CustomTracerMock) Stop() error {
	return nil
}

func (c CustomTracerMock) Name() string {
	return ""
}
