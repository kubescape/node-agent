package processtree

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
)

type ProcessTreeManager interface {
	Start()
	Stop()
	GetContainerProcessTree(containerID string, pid uint32, useCache bool) (apitypes.Process, error)
	ReportEvent(eventType utils.EventType, event utils.K8sEvent) error
	GetPidList() []uint32
}
