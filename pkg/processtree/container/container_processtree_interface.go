package containerprocesstree

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type ContainerProcessTree interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	GetPidBranch(containerID string, targetPID uint32, fullTree *maps.SafeMap[uint32, *armotypes.Process]) (armotypes.Process, error)
	IsProcessUnderAnyContainerSubtree(pid uint32, fullTree *maps.SafeMap[uint32, *armotypes.Process]) bool
	IsProcessUnderContainer(pid uint32, containerID string, fullTree *maps.SafeMap[uint32, *armotypes.Process]) bool
	GetPidByContainerID(containerID string) (uint32, error)
	GetShimPIDForProcess(pid uint32, fullTree *maps.SafeMap[uint32, *armotypes.Process]) (uint32, bool)
}
