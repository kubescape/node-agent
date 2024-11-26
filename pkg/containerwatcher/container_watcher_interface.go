package containerwatcher

import (
	"context"
)

type ContainerWatcher interface {
	Ready() bool
	Start(ctx context.Context) error
	Stop()
}
