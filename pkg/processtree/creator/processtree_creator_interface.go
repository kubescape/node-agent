package processtreecreator

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
)

type ProcessTreeCreator interface {
	// Feed a new event into the process tree
	FeedEvent(event feeder.ProcessEvent)
	// Get the full process tree (returns the root or all processes)
	GetNodeTree() ([]apitypes.Process, error)
	// Optionally: Query for a process node by PID
	GetProcessNode(pid int) (*apitypes.Process, error)
}
