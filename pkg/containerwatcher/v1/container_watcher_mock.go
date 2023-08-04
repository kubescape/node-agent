package containerwatcher

import (
	"context"
	"node-agent/pkg/containerwatcher"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type ContainerWatcherMock struct{}

func (c ContainerWatcherMock) Start(_ context.Context) error {
	return nil
}

func (c ContainerWatcherMock) Stop() {}

func (c ContainerWatcherMock) UnregisterContainer(_ *containercollection.Container) {}

var _ containerwatcher.ContainerWatcher = (*ContainerWatcherMock)(nil)
