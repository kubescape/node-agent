package containerwatcher

import (
	"context"
)

type ContainerWatcher interface {
	Start(ctx context.Context) error
	Stop()
	UnregisterContainer(ctx context.Context, containerEventData ContainerEvent)
}
