package processtree

import (
	"context"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

type ProcessTreeManager interface {
	Start(ctx context.Context) error
	Stop() error
	GetHostProcessTree() ([]apitypes.Process, error)
	GetContainerProcessTree(containerID string, pid uint32) (apitypes.Process, error)
	GetProcessNode(pid int) (*apitypes.Process, error)
	WaitForProcessProcessing(pid uint32, startTimeNs uint64, timeout time.Duration) error
}
