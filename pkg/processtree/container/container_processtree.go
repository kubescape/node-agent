package containerprocesstree

import (
	"fmt"
	"sync"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/prometheus/procfs"
)

type containerProcessTreeImpl struct {
	containerIdToShimPid map[string]uint32
	mutex                sync.RWMutex
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
		c.mutex.RLock()
		_, exists := c.containerIdToShimPid[containerID]
		c.mutex.RUnlock()

		if exists {
			logger.L().Debug("Container already exists in process tree", helpers.String("containerID", containerID))
			return
		}

		containerPID := notif.Container.ContainerPid()
		if process, err := c.getProcessFromProc(int(containerPID)); err == nil {
			shimPID := process.PPID
			c.mutex.Lock()
			c.containerIdToShimPid[containerID] = shimPID
			c.mutex.Unlock()
			logger.L().Info("ContainerProcessTree.ContainerCallback - added container", helpers.String("containerID", containerID), helpers.Interface("shimPID", shimPID))
		} else {
			logger.L().Warning("ContainerProcessTree.ContainerCallback - failed to get container process info",
				helpers.String("containerID", containerID),
				helpers.Error(err))
		}
	case containercollection.EventTypeRemoveContainer:
		c.mutex.Lock()
		delete(c.containerIdToShimPid, containerID)
		c.mutex.Unlock()
		logger.L().Info("ContainerProcessTree.ContainerCallback - removed container", helpers.String("containerID", containerID))
	}
}

func (c *containerProcessTreeImpl) GetContainerTreeNodes(containerID string, fullTree map[uint32]*apitypes.Process) ([]apitypes.Process, error) {
	c.mutex.RLock()
	shimPID, ok := c.containerIdToShimPid[containerID]
	c.mutex.RUnlock()

	if !ok {
		return nil, nil
	}

	// Find the process node for the shim PID
	shimNode := fullTree[shimPID]
	if shimNode == nil {
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

// GetPidBranch returns the branch of the process tree from the target PID
// up to (but not including) the containerd-shim process. This returns a process
// tree containing only the nodes along the path from target to shim.
func (c *containerProcessTreeImpl) GetPidBranch(containerID string, targetPID uint32, fullTree map[uint32]*apitypes.Process) (apitypes.Process, error) {
	c.mutex.RLock()
	shimPID, ok := c.containerIdToShimPid[containerID]
	c.mutex.RUnlock()

	if !ok {
		return apitypes.Process{}, fmt.Errorf("container %s not found", containerID)
	}

	// Find the process node for the shim PID
	shimNode := fullTree[shimPID]
	if shimNode == nil {
		return apitypes.Process{}, fmt.Errorf("shim process %d not found in process tree", shimPID)
	}

	// Find the target process node
	targetNode := fullTree[targetPID]
	if targetNode == nil {
		return apitypes.Process{}, fmt.Errorf("target process %d not found in process tree", targetPID)
	}

	// Check if the target PID is within the shim's subtree
	if !c.isProcessInSubtree(targetNode, shimNode, fullTree) {
		return apitypes.Process{}, fmt.Errorf("target process %d is not within container %s subtree", targetPID, containerID)
	}

	// Build the branch from target PID up to (but not including) shim
	branch := c.buildBranchToShim(targetNode, shimPID, fullTree)
	if branch == nil {
		return apitypes.Process{}, fmt.Errorf("failed to build branch for target %d", targetPID)
	}

	return *branch, nil
}

func (c *containerProcessTreeImpl) ListContainers() []string {
	c.mutex.RLock()
	ids := make([]string, 0, len(c.containerIdToShimPid))
	for id := range c.containerIdToShimPid {
		ids = append(ids, id)
	}
	c.mutex.RUnlock()
	return ids
}

func (c *containerProcessTreeImpl) IsProcessUnderAnyContainerSubtree(pid uint32, fullTree map[uint32]*apitypes.Process) bool {
	c.mutex.RLock()
	shimPIDs := make([]uint32, 0, len(c.containerIdToShimPid))
	for _, shimPID := range c.containerIdToShimPid {
		shimPIDs = append(shimPIDs, shimPID)
	}
	c.mutex.RUnlock()

	for _, shimPID := range shimPIDs {
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

func (c *containerProcessTreeImpl) GetShimPIDForProcess(pid uint32, fullTree map[uint32]*apitypes.Process) (uint32, bool) {
	c.mutex.RLock()
	shimPIDs := make([]uint32, 0, len(c.containerIdToShimPid))
	for _, shimPID := range c.containerIdToShimPid {
		shimPIDs = append(shimPIDs, shimPID)
	}
	c.mutex.RUnlock()

	for _, shimPID := range shimPIDs {
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

func (c *containerProcessTreeImpl) GetPidByContainerID(containerID string) (uint32, error) {
	c.mutex.RLock()
	shimPID, ok := c.containerIdToShimPid[containerID]
	c.mutex.RUnlock()

	if !ok {
		return 0, fmt.Errorf("container %s not found", containerID)
	}

	return shimPID, nil
}

func (c *containerProcessTreeImpl) isProcessInSubtree(targetNode, rootNode *apitypes.Process, fullTree map[uint32]*apitypes.Process) bool {
	if targetNode == nil || rootNode == nil {
		return false
	}

	if targetNode.PID == rootNode.PID {
		return true
	}

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

// buildBranchToShim builds a process tree branch from targetNode up to (but not including) shimPID
// This creates a new process tree containing only the nodes along the path from target to shim
func (c *containerProcessTreeImpl) buildBranchToShim(targetNode *apitypes.Process, shimPID uint32, fullTree map[uint32]*apitypes.Process) *apitypes.Process {

	// Create a map to store the branch nodes
	branchNodes := make(map[uint32]*apitypes.Process)

	if targetNode == nil {
		return nil
	}

	var pathNodes []*apitypes.Process
	current := targetNode
	for current.PPID != 0 {
		pathNodes = append(pathNodes, current)

		parent := fullTree[current.PPID]
		if parent == nil {
			break
		}

		if parent.PID == shimPID {
			break
		}

		current = parent
	}

	if len(pathNodes) == 0 {
		return nil
	}

	for _, node := range pathNodes {
		branchNodes[node.PID] = &apitypes.Process{
			PID:         node.PID,
			PPID:        node.PPID,
			Comm:        node.Comm,
			Pcomm:       node.Pcomm,
			Cmdline:     node.Cmdline,
			Uid:         node.Uid,
			Gid:         node.Gid,
			Cwd:         node.Cwd,
			Path:        node.Path,
			ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
		}
	}

	for _, node := range pathNodes {
		branchNode := branchNodes[node.PID]
		if branchNode.PPID != 0 && branchNode.PPID != shimPID {
			if parentBranch, exists := branchNodes[branchNode.PPID]; exists {
				key := apitypes.CommPID{Comm: branchNode.Comm, PID: branchNode.PID}
				parentBranch.ChildrenMap[key] = branchNode
			}
		}
	}

	for _, node := range pathNodes {
		if node.PPID == shimPID {
			return branchNodes[node.PID]
		}
	}

	return branchNodes[shimPID]
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
