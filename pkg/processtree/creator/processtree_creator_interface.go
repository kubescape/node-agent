package processtreecreator

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
)

type ProcessTreeCreator interface {
	// Feed a new event into the process tree
	FeedEvent(event conversion.ProcessEvent)
	// Get the full process tree (returns the root or all processes)
	GetRootTree() ([]armotypes.Process, error)
	// Get the process map
	GetProcessMap() *maps.SafeMap[uint32, *armotypes.Process]
	// Optionally: Query for a process node by PID
	GetProcessNode(pid int) (*armotypes.Process, error)
	// GetProcessBootTimeNs returns the process's creation time as nanoseconds
	// since boot (CLOCK_BOOTTIME), sourced exclusively from /proc/<pid>/stat
	// field 22. Returns 0 when unknown (process not yet seen, or already exited).
	GetProcessBootTimeNs(pid uint32) uint64
	// Start the process tree creator and begin background tasks
	Start()
	// Stop the process tree creator and cleanup resources
	Stop()
}
