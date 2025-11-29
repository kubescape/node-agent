package containerprocesstree

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type ContainerProcessTree interface {
	// ContainerCallback handles container lifecycle events from the container collection
	ContainerCallback(notif containercollection.PubSubEvent)

	// GetPidBranch returns the process tree branch for a specific PID within a container
	GetPidBranch(containerID string, targetPID uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) (apitypes.Process, error)

	// IsProcessUnderAnyContainerSubtree checks if a PID is under any registered container's subtree
	IsProcessUnderAnyContainerSubtree(pid uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) bool

	// IsProcessUnderContainer checks if a PID is under a specific container's subtree
	IsProcessUnderContainer(pid uint32, containerID string, fullTree *maps.SafeMap[uint32, *apitypes.Process]) bool

	// GetPidByContainerID returns the shim PID (or container PID as fallback) for a container
	GetPidByContainerID(containerID string) (uint32, error)

	// GetShimPIDForProcess finds the shim PID that a process belongs to
	GetShimPIDForProcess(pid uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) (uint32, bool)

	// RegisterContainerShim registers or updates a container's shim PID
	// This is called when we discover the shim PID from process events (fork/exec)
	// It enables lazy shim discovery for containers that were registered before
	// their shim PID could be determined from /proc
	RegisterContainerShim(containerID string, shimPID uint32, containerPID uint32)
}
