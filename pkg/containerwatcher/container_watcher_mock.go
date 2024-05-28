package containerwatcher

import (
	"context"
)

type ContainerWatcherMock struct{}

func (c ContainerWatcherMock) Ready() bool {
	return true
}

func (c ContainerWatcherMock) Start(_ context.Context) error {
	return nil
}

func (c ContainerWatcherMock) Stop() {}

var _ ContainerWatcher = (*ContainerWatcherMock)(nil)
