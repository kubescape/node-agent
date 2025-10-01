package processtreecreator

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
)

type ProcessTreeCreator interface {
	// Feed a new event into the process tree
	FeedEvent(event conversion.ProcessEvent)
	// Get the full process tree (returns the root or all processes)
	GetRootTree() ([]apitypes.Process, error)
	// Get the process map
	GetProcessMap() *maps.SafeMap[uint32, *apitypes.Process]
	// Optionally: Query for a process node by PID
	GetProcessNode(pid int) (*apitypes.Process, error)
	// Get the container ID for a PID
	GetContainerIDForPid(pid uint32) (string, error)
	// Start the process tree creator and begin background tasks
	Start()
	// Stop the process tree creator and cleanup resources
	Stop()
}
