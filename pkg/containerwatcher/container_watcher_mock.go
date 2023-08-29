package containerwatcher

import (
	"context"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type ContainerWatcherMock struct{}

func (c ContainerWatcherMock) Start(_ context.Context) error {
	return nil
}

func (c ContainerWatcherMock) Stop() {}

func (c ContainerWatcherMock) UnregisterContainer(_ *containercollection.Container) {}

var _ ContainerWatcher = (*ContainerWatcherMock)(nil)
