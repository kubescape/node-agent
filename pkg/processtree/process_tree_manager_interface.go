package processtree

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
)

type ProcessTreeManager interface {
	GetHostProcessTree() ([]apitypes.Process, error)
	GetContainerProcessTree(containerID string, pid uint32) (apitypes.Process, error)
	ReportEvent(eventType utils.EventType, event utils.K8sEvent) error
}
