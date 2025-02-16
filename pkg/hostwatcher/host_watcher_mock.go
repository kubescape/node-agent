package hostwatcher

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
)

type HostWatcherMock struct{}

func (c HostWatcherMock) Ready() bool {
	return true
}

func (c HostWatcherMock) Start(_ context.Context) error {
	return nil
}

func (c HostWatcherMock) Stop() {}

func (c HostWatcherMock) RegisterCustomTracer(_ CustomTracer) error {
	return nil
}

func (c HostWatcherMock) UnregisterCustomTracer(_ CustomTracer) error {
	return nil
}

func (c HostWatcherMock) GetTracerCollection() *tracercollection.TracerCollection {
	return nil
}

func (c HostWatcherMock) GetSocketEnricher() *socketenricher.SocketEnricher {
	return nil
}

var _ HostWatcher = (*HostWatcherMock)(nil)

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

var _ CustomTracer = (*CustomTracerMock)(nil)
