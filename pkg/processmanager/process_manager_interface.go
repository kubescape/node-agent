package processmanager

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/utils"
)

// ProcessManagerClient is the interface for the process manager client.
// It provides methods to get process tree for a container or a PID.
// The manager is responsible for maintaining the process tree for all containers.
type ProcessManagerClient interface {
	GetProcessTreeForPID(containerID string, pid apitypes.CommPID) (apitypes.Process, error)
	// PopulateInitialProcesses is called to populate the initial process tree (parsed from /proc) for all containers.
	PopulateInitialProcesses() error

	// ReportEvent will be called to report new exec events to the process manager.
	ReportEvent(eventType utils.EventType, event utils.K8sEvent)
	ContainerCallback(notif containercollection.PubSubEvent)
}
