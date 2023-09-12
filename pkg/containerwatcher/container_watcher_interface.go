package containerwatcher

import (
	"context"
)

type ContainerWatcher interface {
	Start(ctx context.Context) error
	Stop()
}
