package strategies

import (
	"fmt"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

// ContainerdStrategy handles reparenting for containerd-based containers
type ContainerdStrategy struct{}

func (cs *ContainerdStrategy) Name() string {
	return "containerd"
}

// IsApplicable checks if this strategy is applicable for the given scenario
// It checks if the exiting process is under any containerd-shim subtree
func (cs *ContainerdStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	// Check if the exiting process is under a containerd-shim subtree
	return containerTree != nil && containerTree.IsProcessUnderAnyContainerSubtree(exitingPID, processMap)
}

// GetNewParentPID determines the new parent PID for orphaned children
// For containerd, orphaned processes are typically reparented to the shim process
func (cs *ContainerdStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	// For containerd, orphaned processes are typically reparented to the shim process
	if containerTree != nil {
		shimPID, found := containerTree.GetShimPIDForProcess(exitingPID, processMap)
		if found {
			logger.L().Info("ContainerdStrategy: Reparenting to shim",
				helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)),
				helpers.String("shim_pid", fmt.Sprintf("%d", shimPID)))
			return shimPID
		}
	}

	// Fallback to init process if shim not found or containerTree is nil
	logger.L().Warning("ContainerdStrategy: Shim not found or containerTree is nil, falling back to init",
		helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)))
	return 1
}
