package processtree

import (
	"context"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

type ProcessTreeManager interface {
	Start(ctx context.Context) error
	Stop() error
	GetHostProcessTree() ([]apitypes.Process, error)
	GetContainerProcessTree(containerID string) ([]apitypes.Process, error)
	GetProcessNode(pid int) (*apitypes.Process, error)
}
