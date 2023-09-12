package containerwatcher

import (
	"context"
)

type ContainerWatcher interface {
	PeekSyscallInContainer(nsMountId uint64) ([]string, error)
	Start(ctx context.Context) error
	Stop()
}
