package strategies

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

// ContainerStrategy handles reparenting for containerd-based containers
type ContainerStrategy struct{}

func (cs *ContainerStrategy) Name() string {
	return "containerized_env"
}

func (cs *ContainerStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	return containerTree != nil && containerTree.IsProcessUnderAnyContainerSubtree(exitingPID, processMap)
}

func (cs *ContainerStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	if containerTree != nil {
		shimPID, found := containerTree.GetShimPIDForProcess(exitingPID, processMap)
		if found {
			return shimPID
		}
	}

	return 1
}
