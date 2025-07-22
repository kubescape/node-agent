package processtree

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
)

type ProcessTreeManager interface {
	// Start initializes the process tree manager and starts background tasks
	Start()
	// Stop shuts down the process tree manager and stops background tasks
	Stop()
	GetHostProcessTree(pid uint32) (apitypes.Process, error)
	GetContainerProcessTree(containerID string, pid uint32, useCache bool) (apitypes.Process, error)
	ReportEvent(eventType utils.EventType, event utils.K8sEvent) error
}
