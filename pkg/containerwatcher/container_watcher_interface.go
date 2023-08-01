package containerwatcher

import (
	"context"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type ContainerWatcher interface {
	Start(ctx context.Context) error
	Stop()
	UnregisterContainer(container *containercollection.Container)
}
