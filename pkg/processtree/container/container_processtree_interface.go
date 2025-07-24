package containerprocesstree

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type ContainerProcessTree interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	GetPidBranch(containerID string, targetPID uint32, fullTree map[uint32]*apitypes.Process) (apitypes.Process, error)
	IsProcessUnderAnyContainerSubtree(pid uint32, fullTree map[uint32]*apitypes.Process) bool
	IsProcessUnderContainer(pid uint32, containerID string, fullTree map[uint32]*apitypes.Process) bool
	GetPidByContainerID(containerID string) (uint32, error)
	GetShimPIDForProcess(pid uint32, fullTree map[uint32]*apitypes.Process) (uint32, bool)
}
