package containerprocesstree

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type ContainerProcessTree interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	GetContainerTreeNodes(containerID string, fullTree map[uint32]*apitypes.Process) ([]apitypes.Process, error)
	GetContainerSubtree(containerID string, targetPID uint32, fullTree map[uint32]*apitypes.Process) (apitypes.Process, error)
	ListContainers() []string
	// Check if a process is under any containerd-shim subtree
	IsProcessUnderAnyContainerSubtree(pid uint32, fullTree map[uint32]*apitypes.Process) bool
	// Get the shim PID for a given process if it's under a container subtree
	GetShimPIDForProcess(pid uint32, fullTree map[uint32]*apitypes.Process) (uint32, bool)
	// Check if a PPID is under any container subtree
	IsPPIDUnderAnyContainerSubtree(ppid uint32, fullTree map[uint32]*apitypes.Process) bool
	// SetShimPIDForTesting manually sets the shim PID for a container (for testing purposes only)
	SetShimPIDForTesting(containerID string, shimPID uint32)
}
