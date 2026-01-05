package strategies

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

// ContainerStrategy handles reparenting for containerd-based containers
type ContainerStrategy struct{}

func (cs *ContainerStrategy) Name() string {
	return "containerized_env"
}

func (cs *ContainerStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap *maps.SafeMap[uint32, *apitypes.Process]) bool {
	return containerTree != nil && containerTree.IsProcessUnderAnyContainerSubtree(exitingPID, processMap)
}

func (cs *ContainerStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap *maps.SafeMap[uint32, *apitypes.Process]) uint32 {
	if containerTree != nil {
		shimPID, found := containerTree.GetShimPIDForProcess(exitingPID, processMap)
		if found {
			// If the exiting process is the container init process (direct child of shim),
			// its children should be reparented to the shim
			if proc, ok := processMap.Load(exitingPID); ok && proc.PPID == shimPID {
				return shimPID
			}

			// Otherwise, find the container init process (child of shim)
			// We walk up the tree from the exiting process until we find the process that is a direct child of the shim
			currentPID := exitingPID
			for {
				proc, ok := processMap.Load(currentPID)
				if !ok {
					break
				}
				if proc.PPID == shimPID {
					return proc.PID
				}
				if proc.PPID == 0 {
					break
				}
				currentPID = proc.PPID
			}
			return shimPID
		}
	}

	return 1
}
