package containerprocesstree

import (
	"fmt"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/prometheus/procfs"
)

type containerProcessTreeImpl struct {
	containerIdToShimPid map[string]uint32
}

func NewContainerProcessTree() ContainerProcessTree {
	return &containerProcessTreeImpl{
		containerIdToShimPid: make(map[string]uint32),
	}
}

func (c *containerProcessTreeImpl) ContainerCallback(notif containercollection.PubSubEvent) {
	containerID := notif.Container.Runtime.BasicRuntimeMetadata.ContainerID

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		// Check if container already exists before adding
		if _, exists := c.containerIdToShimPid[containerID]; exists {
			logger.L().Debug("Container already exists in process tree", helpers.String("containerID", containerID))
			return
		}
		containerPID := notif.Container.ContainerPid()
		if process, err := c.getProcessFromProc(int(containerPID)); err == nil {
			shimPID := process.PPID
			c.containerIdToShimPid[containerID] = shimPID
		} else {
			logger.L().Warning("ContainerProcessTree.ContainerCallback - failed to get container process info",
				helpers.String("containerID", containerID),
				helpers.Error(err))
		}
	case containercollection.EventTypeRemoveContainer:
		delete(c.containerIdToShimPid, containerID)
	}
}

func (c *containerProcessTreeImpl) GetContainerTreeNodes(containerID string, fullTree map[uint32]*apitypes.Process) ([]apitypes.Process, error) {
	shimPID, ok := c.containerIdToShimPid[containerID]
	if !ok {
		logger.L().Debug("GetContainerTree Not found Shim PID", helpers.String("containerID", containerID), helpers.Interface("shimPID", shimPID))
		return nil, nil
	}

	// Find the process node for the shim PID
	shimNode := fullTree[shimPID]
	if shimNode == nil {
		logger.L().Debug("GetContainerTree Not found Shim PID", helpers.String("containerID", containerID), helpers.Interface("shimPID", shimPID))
		return nil, nil
	}

	// Recursively collect all descendants of the shim node
	var result []apitypes.Process
	var collect func(p *apitypes.Process)
	collect = func(p *apitypes.Process) {
		result = append(result, *p)
		for _, child := range p.ChildrenMap {
			collect(child)
		}
	}
	collect(shimNode)
	return result, nil
}

func (c *containerProcessTreeImpl) GetContainerSubtree(containerID string, targetPID uint32, fullTree map[uint32]*apitypes.Process) (apitypes.Process, error) {
	shimPID, ok := c.containerIdToShimPid[containerID]
	if !ok {
		logger.L().Debug("GetContainerSubtree Not found Shim PID", helpers.String("containerID", containerID), helpers.Interface("shimPID", shimPID))
		return apitypes.Process{}, fmt.Errorf("container %s not found", containerID)
	}

	// Find the process node for the shim PID
	shimNode := fullTree[shimPID]
	if shimNode == nil {
		logger.L().Debug("GetContainerSubtree Not found Shim PID", helpers.String("containerID", containerID), helpers.Interface("shimPID", shimPID))
		return apitypes.Process{}, fmt.Errorf("shim process %d not found in process tree", shimPID)
	}

	// Find the target process node
	targetNode := fullTree[targetPID]
	if targetNode == nil {
		logger.L().Debug("GetContainerSubtree Target PID not found", helpers.String("containerID", containerID), helpers.Interface("targetPID", targetPID))
		return apitypes.Process{}, fmt.Errorf("target process %d not found in process tree", targetPID)
	}

	// Check if the target PID is within the shim's subtree
	if !c.isProcessInSubtree(targetNode, shimNode, fullTree) {
		return apitypes.Process{}, fmt.Errorf("target process %d is not within container %s subtree", targetPID, containerID)
	}

	// Walk up the parent chain from target PID until we reach the node just before shim PID
	rootNode := c.findRootNodeBeforeShim(targetNode, shimPID, fullTree)
	if rootNode == nil {
		return apitypes.Process{}, fmt.Errorf("failed to find root node before shim for target %d", targetPID)
	}

	return *rootNode.DeepCopy(), nil
}

// isProcessInSubtree checks if a process is within the subtree of a given root node
func (c *containerProcessTreeImpl) isProcessInSubtree(targetNode, rootNode *apitypes.Process, fullTree map[uint32]*apitypes.Process) bool {
	if targetNode == nil || rootNode == nil {
		return false
	}

	// If target is the root, it's in the subtree
	if targetNode.PID == rootNode.PID {
		return true
	}

	// Walk up the parent chain from target until we find the root or reach the top
	current := targetNode
	for current.PPID != 0 {
		if current.PPID == rootNode.PID {
			return true
		}
		parent := fullTree[current.PPID]
		if parent == nil {
			break
		}
		current = parent
	}

	return false
}

// findRootNodeBeforeShim walks up the parent chain from targetNode until reaching the node just before shimPID
func (c *containerProcessTreeImpl) findRootNodeBeforeShim(targetNode *apitypes.Process, shimPID uint32, fullTree map[uint32]*apitypes.Process) *apitypes.Process {
	if targetNode == nil {
		return nil
	}

	// Walk up the parent chain until we find the node whose parent is the shim
	current := targetNode
	for current.PPID != 0 {
		parent := fullTree[current.PPID]
		if parent == nil {
			break
		}

		// If the parent is the shim PID, we've found our root (the current node)
		if parent.PID == shimPID {
			return current
		}

		current = parent
	}

	// If we reach here, the target node itself is the root (no parent found that leads to shim)
	return current
}

func (c *containerProcessTreeImpl) ListContainers() []string {
	ids := make([]string, 0, len(c.containerIdToShimPid))
	for id := range c.containerIdToShimPid {
		ids = append(ids, id)
	}
	return ids
}

// SetShimPIDForTesting manually sets the shim PID for a container (for testing purposes only)
func (c *containerProcessTreeImpl) SetShimPIDForTesting(containerID string, shimPID uint32) {
	c.containerIdToShimPid[containerID] = shimPID
}

// IsProcessUnderAnyContainerSubtree checks if a process is under any containerd-shim subtree
func (c *containerProcessTreeImpl) IsProcessUnderAnyContainerSubtree(pid uint32, fullTree map[uint32]*apitypes.Process) bool {
	// Check each container's shim subtree
	for _, shimPID := range c.containerIdToShimPid {
		shimNode := fullTree[shimPID]
		if shimNode == nil {
			continue
		}

		targetNode := fullTree[pid]
		if targetNode == nil {
			continue
		}

		if c.isProcessInSubtree(targetNode, shimNode, fullTree) {
			return true
		}
	}
	return false
}

// GetShimPIDForProcess returns the shim PID for a given process if it's under a container subtree
func (c *containerProcessTreeImpl) GetShimPIDForProcess(pid uint32, fullTree map[uint32]*apitypes.Process) (uint32, bool) {
	// Check each container's shim subtree
	for _, shimPID := range c.containerIdToShimPid {
		shimNode := fullTree[shimPID]
		if shimNode == nil {
			continue
		}

		targetNode := fullTree[pid]
		if targetNode == nil {
			continue
		}

		if c.isProcessInSubtree(targetNode, shimNode, fullTree) {
			return shimPID, true
		}
	}
	return 0, false
}

// IsPPIDUnderAnyContainerSubtree checks if a PPID is under any container subtree
func (c *containerProcessTreeImpl) IsPPIDUnderAnyContainerSubtree(ppid uint32, fullTree map[uint32]*apitypes.Process) bool {
	// Check each container's shim subtree
	for _, shimPID := range c.containerIdToShimPid {
		shimNode := fullTree[shimPID]
		if shimNode == nil {
			continue
		}

		ppidNode := fullTree[ppid]
		if ppidNode == nil {
			continue
		}

		if c.isProcessInSubtree(ppidNode, shimNode, fullTree) {
			return true
		}
	}
	return false
}

// getProcessFromProc retrieves process information from the /proc filesystem
// for a given PID. This is a simplified version of the process manager's implementation.
func (c *containerProcessTreeImpl) getProcessFromProc(pid int) (*apitypes.Process, error) {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get process info: %v", err)
	}

	stat, err := proc.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get process stat: %v", err)
	}

	return &apitypes.Process{
		PID:   uint32(pid),
		PPID:  uint32(stat.PPID),
		Comm:  stat.Comm,
		Pcomm: stat.Comm, // For simplicity, using the same as Comm
	}, nil
}
