package containerprocesstree

import (
	"fmt"
	"sync"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/prometheus/procfs"
)

// containerInfo holds information about a registered container
type containerInfo struct {
	shimPID      uint32    // The shim/parent PID (0 if not yet discovered)
	containerPID uint32    // The container's init PID
	registeredAt time.Time // When the container was registered
}

type containerProcessTreeImpl struct {
	containerIdToInfo map[string]*containerInfo
	mutex             sync.RWMutex
}

func NewContainerProcessTree() ContainerProcessTree {
	return &containerProcessTreeImpl{
		containerIdToInfo: make(map[string]*containerInfo),
	}
}

func (c *containerProcessTreeImpl) ContainerCallback(notif containercollection.PubSubEvent) {
	containerID := notif.Container.Runtime.BasicRuntimeMetadata.ContainerID

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		// Check if container already exists before adding
		c.mutex.RLock()
		_, exists := c.containerIdToInfo[containerID]
		c.mutex.RUnlock()

		if exists {
			logger.L().Debug("Container already exists in process tree", helpers.String("containerID", containerID))
			return
		}

		containerPID := notif.Container.ContainerPid()
		info := &containerInfo{
			containerPID: containerPID,
			registeredAt: time.Now(),
		}

		// Try to get shim PID from /proc
		if process, err := c.getProcessFromProc(int(containerPID)); err == nil {
			info.shimPID = process.PPID
			c.mutex.Lock()
			c.containerIdToInfo[containerID] = info
			c.mutex.Unlock()

			logger.L().Info("ContainerProcessTree.ContainerCallback - added container with shim",
				helpers.String("containerID", containerID),
				helpers.Interface("shimPID", info.shimPID),
				helpers.Interface("containerPID", containerPID))
		} else {
			// FIX: Register the container even without shim PID
			// We'll discover the shim PID later from the process tree or /proc
			c.mutex.Lock()
			c.containerIdToInfo[containerID] = info
			c.mutex.Unlock()

			logger.L().Warning("ContainerProcessTree.ContainerCallback - added container without shim (will discover later)",
				helpers.String("containerID", containerID),
				helpers.Interface("containerPID", containerPID),
				helpers.Error(err))
		}

	case containercollection.EventTypeRemoveContainer:
		c.mutex.Lock()
		delete(c.containerIdToInfo, containerID)
		c.mutex.Unlock()

		logger.L().Info("ContainerProcessTree.ContainerCallback - removed container", helpers.String("containerID", containerID))
	}
}

// RegisterContainerShim allows registering or updating a container's shim PID
// This is called when we discover the shim PID from process events (fork/exec)
func (c *containerProcessTreeImpl) RegisterContainerShim(containerID string, shimPID uint32, containerPID uint32) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	info, exists := c.containerIdToInfo[containerID]
	if !exists {
		// Container not yet registered, create new entry
		c.containerIdToInfo[containerID] = &containerInfo{
			shimPID:      shimPID,
			containerPID: containerPID,
			registeredAt: time.Now(),
		}
		return
	}

	// Update existing entry if shim was pending (0)
	if info.shimPID == 0 && shimPID != 0 {
		info.shimPID = shimPID
		logger.L().Info("ContainerProcessTree - discovered shim PID for container",
			helpers.String("containerID", containerID),
			helpers.Interface("shimPID", shimPID))
	}
}

// tryDiscoverShimPID attempts to discover the shim PID for a container from the process tree
// Returns the shim PID if found, 0 otherwise
func (c *containerProcessTreeImpl) tryDiscoverShimPID(containerID string, fullTree *maps.SafeMap[uint32, *apitypes.Process]) uint32 {
	c.mutex.RLock()
	info := c.containerIdToInfo[containerID]
	c.mutex.RUnlock()

	if info == nil {
		return 0
	}

	// If we already have a shim PID, return it
	if info.shimPID != 0 {
		return info.shimPID
	}

	// Try to find the container PID in the process tree and get its parent
	if info.containerPID != 0 {
		if proc, ok := fullTree.Load(info.containerPID); ok && proc.PPID != 0 {
			// Found the container process, use its parent as shim
			c.mutex.Lock()
			info.shimPID = proc.PPID
			c.mutex.Unlock()

			logger.L().Info("ContainerProcessTree - discovered shim PID from process tree",
				helpers.String("containerID", containerID),
				helpers.Interface("shimPID", proc.PPID),
				helpers.Interface("containerPID", info.containerPID))

			return proc.PPID
		}
	}

	// Try to get shim PID from /proc again (process might be available now)
	if info.containerPID != 0 {
		if process, err := c.getProcessFromProc(int(info.containerPID)); err == nil && process.PPID != 0 {
			c.mutex.Lock()
			info.shimPID = process.PPID
			c.mutex.Unlock()

			logger.L().Info("ContainerProcessTree - discovered shim PID from /proc",
				helpers.String("containerID", containerID),
				helpers.Interface("shimPID", process.PPID),
				helpers.Interface("containerPID", info.containerPID))

			return process.PPID
		}
	}

	return 0
}

func (c *containerProcessTreeImpl) GetPidBranch(containerID string, targetPID uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) (apitypes.Process, error) {
	// First try to get existing shim PID
	c.mutex.RLock()
	info := c.containerIdToInfo[containerID]
	c.mutex.RUnlock()

	if info == nil {
		return apitypes.Process{}, fmt.Errorf("container %s not found", containerID)
	}

	shimPID := info.shimPID

	// If shim PID is not yet known, try to discover it
	if shimPID == 0 {
		shimPID = c.tryDiscoverShimPID(containerID, fullTree)
		if shimPID == 0 {
			// Still can't find shim, try using container PID as anchor (fallback)
			if info.containerPID != 0 {
				return c.buildBranchToAnchor(targetPID, info.containerPID, fullTree)
			}
			return apitypes.Process{}, fmt.Errorf("shim PID not yet discovered for container %s", containerID)
		}
	}

	// Find the process node for the shim PID
	shimNode, ok := fullTree.Load(shimPID)
	if !ok {
		return apitypes.Process{}, fmt.Errorf("shim process %d not found in process tree", shimPID)
	}

	// Find the target process node
	targetNode, ok := fullTree.Load(targetPID)
	if !ok {
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

// buildBranchToAnchor builds a branch from targetPID up to anchorPID (used when shim is unknown)
func (c *containerProcessTreeImpl) buildBranchToAnchor(targetPID, anchorPID uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) (apitypes.Process, error) {
	targetNode, ok := fullTree.Load(targetPID)
	if !ok {
		return apitypes.Process{}, fmt.Errorf("target process %d not found in process tree", targetPID)
	}

	// Build path from target to anchor (or as far as we can go)
	var pathNodes []*apitypes.Process
	current := targetNode
	for current != nil {
		pathNodes = append(pathNodes, current)
		if current.PID == anchorPID || current.PPID == 0 {
			break
		}
		parent, ok := fullTree.Load(current.PPID)
		if !ok {
			break
		}
		current = parent
	}

	if len(pathNodes) == 0 {
		return apitypes.Process{}, fmt.Errorf("failed to build branch for target %d", targetPID)
	}

	// Build the branch structure
	branchNodes := make(map[uint32]*apitypes.Process)
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

	// Link children to parents
	for _, node := range pathNodes {
		branchNode := branchNodes[node.PID]
		if parentBranch, exists := branchNodes[branchNode.PPID]; exists {
			key := apitypes.CommPID{Comm: branchNode.Comm, PID: branchNode.PID}
			parentBranch.ChildrenMap[key] = branchNode
		}
	}

	// Return the root of the branch (highest in the tree)
	root := branchNodes[pathNodes[len(pathNodes)-1].PID]
	return *root, nil
}

func (c *containerProcessTreeImpl) GetShimPIDForProcess(pid uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) (uint32, bool) {
	c.mutex.RLock()
	shimPIDs := make([]uint32, 0, len(c.containerIdToInfo))
	containerPIDs := make(map[uint32]string) // containerPID -> containerID for fallback
	for containerID, info := range c.containerIdToInfo {
		if info.shimPID != 0 {
			shimPIDs = append(shimPIDs, info.shimPID)
		}
		if info.containerPID != 0 {
			containerPIDs[info.containerPID] = containerID
		}
	}
	c.mutex.RUnlock()

	// First try with known shim PIDs
	for _, shimPID := range shimPIDs {
		shimNode, ok := fullTree.Load(shimPID)
		if !ok {
			continue
		}

		targetNode, ok := fullTree.Load(pid)
		if !ok {
			continue
		}

		if c.isProcessInSubtree(targetNode, shimNode, fullTree) {
			return shimPID, true
		}
	}

	// Fallback: check if pid is under any container PID
	for containerPID, containerID := range containerPIDs {
		containerNode, ok := fullTree.Load(containerPID)
		if !ok {
			continue
		}

		targetNode, ok := fullTree.Load(pid)
		if !ok {
			continue
		}

		if c.isProcessInSubtree(targetNode, containerNode, fullTree) {
			// Try to discover shim from container's parent
			shimPID := c.tryDiscoverShimPID(containerID, fullTree)
			if shimPID != 0 {
				return shimPID, true
			}
			// Return container PID as shim if we can't find actual shim
			return containerPID, true
		}
	}

	return 0, false
}

func (c *containerProcessTreeImpl) GetPidByContainerID(containerID string) (uint32, error) {
	c.mutex.RLock()
	info := c.containerIdToInfo[containerID]
	c.mutex.RUnlock()

	if info == nil {
		return 0, fmt.Errorf("container %s not found", containerID)
	}

	// Return shim PID if known, otherwise return container PID as fallback
	if info.shimPID != 0 {
		return info.shimPID, nil
	}

	if info.containerPID != 0 {
		return info.containerPID, nil
	}

	return 0, fmt.Errorf("no PID available for container %s", containerID)
}

func (c *containerProcessTreeImpl) IsProcessUnderAnyContainerSubtree(pid uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) bool {
	c.mutex.RLock()
	containerIDs := make([]string, 0, len(c.containerIdToInfo))
	for containerID := range c.containerIdToInfo {
		containerIDs = append(containerIDs, containerID)
	}
	c.mutex.RUnlock()

	for _, containerID := range containerIDs {
		if c.IsProcessUnderContainer(pid, containerID, fullTree) {
			return true
		}
	}
	return false
}

func (c *containerProcessTreeImpl) IsProcessUnderContainer(pid uint32, containerID string, fullTree *maps.SafeMap[uint32, *apitypes.Process]) bool {
	c.mutex.RLock()
	info := c.containerIdToInfo[containerID]
	c.mutex.RUnlock()

	if info == nil {
		return false
	}

	// Get shim PID, trying to discover if not yet known
	shimPID := info.shimPID
	if shimPID == 0 {
		shimPID = c.tryDiscoverShimPID(containerID, fullTree)
	}

	// Try with shim PID first
	if shimPID != 0 {
		shimNode, ok := fullTree.Load(shimPID)
		if ok {
			targetNode, ok := fullTree.Load(pid)
			if !ok {
				return false
			}
			return c.isProcessInSubtree(targetNode, shimNode, fullTree)
		}
	}

	// Fallback: check if under container PID
	if info.containerPID != 0 {
		containerNode, ok := fullTree.Load(info.containerPID)
		if ok {
			targetNode, ok := fullTree.Load(pid)
			if ok {
				// Check if target is the container itself or under it
				if pid == info.containerPID || c.isProcessInSubtree(targetNode, containerNode, fullTree) {
					return true
				}
			}
		}
	}

	return false
}

func (c *containerProcessTreeImpl) isProcessInSubtree(targetNode, rootNode *apitypes.Process, fullTree *maps.SafeMap[uint32, *apitypes.Process]) bool {
	if targetNode == nil || rootNode == nil {
		return false
	}

	if targetNode.PID == rootNode.PID {
		return true
	}

	current := targetNode
	depth := 0
	maxDepth := 100 // Prevent infinite loops
	for current.PPID != 0 && depth < maxDepth {
		depth++
		if current.PPID == rootNode.PID {
			return true
		}
		parent, ok := fullTree.Load(current.PPID)
		if !ok {
			break
		}
		current = parent
	}

	return false
}

// buildBranchToShim builds a process tree branch from targetNode up to (but not including) shimPID
// This creates a new process tree containing only the nodes along the path from target to shim
func (c *containerProcessTreeImpl) buildBranchToShim(targetNode *apitypes.Process, shimPID uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) *apitypes.Process {

	// Create a map to store the branch nodes
	branchNodes := make(map[uint32]*apitypes.Process)

	if targetNode == nil {
		return nil
	}

	var pathNodes []*apitypes.Process
	current := targetNode
	for current.PPID != 0 {
		pathNodes = append(pathNodes, current)

		parent, ok := fullTree.Load(current.PPID)
		if !ok {
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
		PID:  uint32(pid),
		PPID: uint32(stat.PPID),
		Comm: stat.Comm,
	}, nil
}
