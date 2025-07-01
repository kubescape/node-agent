package processtreecreator

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
)

type ProcessTreeCreator interface {
	// Feed a new event into the process tree
	FeedEvent(event feeder.ProcessEvent)
	// Get the full process tree (returns the root or all processes)
	GetRootTree() ([]apitypes.Process, error)
	// Get the process map
	GetProcessMap() map[uint32]*apitypes.Process
	// Optionally: Query for a process node by PID
	GetProcessNode(pid int) (*apitypes.Process, error)
	// Set the container tree for container-aware PPID management
	SetContainerTree(containerTree containerprocesstree.ContainerProcessTree)
}
