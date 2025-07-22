package processtreecreator

import (
	"fmt"
	"sync"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/kubescape/node-agent/pkg/processtree/reparenting"
)

type processTreeCreatorImpl struct {
	processMap             maps.SafeMap[uint32, *apitypes.Process] // PID -> Process
	containerTree          containerprocesstree.ContainerProcessTree
	reparenting_strategies reparenting.ReparentingStrategies
	mutex                  sync.RWMutex // Protects process tree modifications
	config                 config.Config

	// Exit manager fields
	pendingExits        map[uint32]*pendingExit // PID -> pending exit
	exitCleanupStopChan chan struct{}
}

func NewProcessTreeCreator(containerTree containerprocesstree.ContainerProcessTree, config config.Config) ProcessTreeCreator {
	// Create reparenting logic
	reparentingLogic, err := reparenting.NewReparentingLogic()
	if err != nil {
		logger.L().Warning("Failed to create reparenting logic, using fallback", helpers.Error(err))
		reparentingLogic = nil
	}

	creator := &processTreeCreatorImpl{
		processMap:             maps.SafeMap[uint32, *apitypes.Process]{},
		reparenting_strategies: reparentingLogic,
		containerTree:          containerTree,
		pendingExits:           make(map[uint32]*pendingExit),
		config:                 config,
	}

	return creator
}

// Start initializes the process tree creator and starts background tasks
func (pt *processTreeCreatorImpl) Start() {
	pt.startExitManager()
}

// Stop shuts down the process tree creator and stops background tasks
func (pt *processTreeCreatorImpl) Stop() {
	pt.stopExitManager()
}

func (pt *processTreeCreatorImpl) FeedEvent(event feeder.ProcessEvent) {
	switch event.Type {
	case feeder.ForkEvent:
		pt.handleForkEvent(event)
	case feeder.ProcfsEvent:
		pt.handleProcfsEvent(event)
	case feeder.ExecEvent:
		pt.handleExecEvent(event)
	case feeder.ExitEvent:
		pt.handleExitEvent(event)
	}
}

func (pt *processTreeCreatorImpl) GetRootTree() ([]apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	// Find root processes (those whose parent is not in the map or PPID==0)
	roots := []apitypes.Process{}
	for _, proc := range pt.processMap.Values() {
		if proc.PPID == 0 || pt.processMap.Get(proc.PPID) == nil {
			roots = append(roots, *proc)
		}
	}
	return roots, nil
}

func (pt *processTreeCreatorImpl) GetProcessMap() map[uint32]*apitypes.Process {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	// Convert SafeMap to regular map for compatibility
	processMap := make(map[uint32]*apitypes.Process)
	pt.processMap.Range(func(pid uint32, proc *apitypes.Process) bool {
		processMap[pid] = proc
		return true
	})
	return processMap
}

func (pt *processTreeCreatorImpl) GetProcessNode(pid int) (*apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	proc := pt.processMap.Get(uint32(pid))
	if proc == nil {
		return nil, nil
	}
	return pt.shallowCopyProcess(proc), nil
}

// GetPidBranch performs container branch operation (no longer needs to be atomic)
func (pt *processTreeCreatorImpl) GetPidBranch(containerTree interface{}, containerID string, targetPID uint32) (apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	// Type assert the container tree
	ct, ok := containerTree.(containerprocesstree.ContainerProcessTree)
	if !ok {
		return apitypes.Process{}, fmt.Errorf("invalid container tree type")
	}

	// Convert SafeMap to regular map for compatibility
	processMap := pt.getProcessMapAsRegularMap()

	// Perform the container branch operation
	return ct.GetPidBranch(containerID, targetPID, processMap)
}

// GetHostProcessBranch builds a process tree branch from the given PID up to the root (init process)
func (pt *processTreeCreatorImpl) GetHostProcessBranch(pid uint32) (apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	// Find the target process
	targetProc := pt.processMap.Get(pid)
	if targetProc == nil {
		return apitypes.Process{}, fmt.Errorf("process with PID %d not found", pid)
	}

	// 1. Extract pid node from full tree - already have it as targetProc
	// 2. Traverse back to the first node (root) by PPID to build the path
	pathToRoot := pt.buildPathToRoot(targetProc)
	if len(pathToRoot) == 0 {
		return apitypes.Process{}, fmt.Errorf("failed to build path to root for PID %d", pid)
	}

	// 3. Return branch node - build the branch from root down to target
	return pt.buildBranchFromPath(pathToRoot), nil
}

// UpdatePPID handles PPID updates using the new reparenting strategy
func (pt *processTreeCreatorImpl) UpdatePPID(proc *apitypes.Process, event feeder.ProcessEvent) {
	if event.PPID != proc.PPID && event.PPID != 0 {
		// New reparenting strategy:
		// 1. If new PPID is under container subtree, update regardless of current state
		// 2. Else if process is already under container, do nothing
		// 3. Else do standard PPID update logic

		// Host mode: update PPID regardless of current state
		if !pt.config.KubernetesMode {
			pt.updateProcessPPID(proc, event.PPID)
			return
		}

		// First check if new PPID is under any container subtree
		IsNewPPIDUnderContainer := pt.containerTree.IsProcessUnderContainer(event.PPID, event.ContainerID, pt.getProcessMapAsRegularMap())
		if IsNewPPIDUnderContainer {
			pt.updateProcessPPID(proc, event.PPID)
		} else {
			isCurrentUnderContainer := pt.containerTree.IsProcessUnderContainer(proc.PID, event.ContainerID, pt.getProcessMapAsRegularMap())
			if !isCurrentUnderContainer {
				pt.updateProcessPPID(proc, event.PPID)
			}
		}
	}
}

// handleForkEvent handles fork events - only fills properties if they are empty or don't exist
func (pt *processTreeCreatorImpl) handleForkEvent(event feeder.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc := pt.processMap.Get(event.PID)

	if proc == nil {
		proc = pt.getOrCreateProcess(event.PID)
	}

	pt.UpdatePPID(proc, event)

	if proc.Comm == "" {
		proc.Comm = event.Comm
	}
	if proc.Pcomm == "" {
		proc.Pcomm = event.Pcomm
	}
	if proc.Cmdline == "" {
		proc.Cmdline = event.Cmdline
	}
	if proc.Uid == nil {
		proc.Uid = event.Uid
	}
	if proc.Gid == nil {
		proc.Gid = event.Gid
	}
	if proc.Cwd == "" {
		proc.Cwd = event.Cwd
	}
	if proc.Path == "" {
		proc.Path = event.Path
	}

	if proc.ChildrenMap == nil {
		proc.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
	}
}

func (pt *processTreeCreatorImpl) handleProcfsEvent(event feeder.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc := pt.processMap.Get(event.PID)

	if proc == nil {
		proc = pt.getOrCreateProcess(event.PID)
	}

	if event.Comm != "" && proc.Comm == "" {
		proc.Comm = event.Comm
	}
	if event.Pcomm != "" && proc.Pcomm == "" {
		proc.Pcomm = event.Pcomm
	}
	if event.Cmdline != "" && proc.Cmdline == "" {
		proc.Cmdline = event.Cmdline
	}
	if event.Uid != nil && proc.Uid == nil {
		proc.Uid = event.Uid
	}
	if event.Gid != nil && proc.Gid == nil {
		proc.Gid = event.Gid
	}
	if event.Cwd != "" && proc.Cwd == "" {
		proc.Cwd = event.Cwd
	}
	if event.Path != "" && proc.Path == "" {
		proc.Path = event.Path
	}

	if proc.ChildrenMap == nil {
		proc.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
	}
}

func (pt *processTreeCreatorImpl) handleExecEvent(event feeder.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc := pt.processMap.Get(event.PID)
	if proc == nil {
		proc = pt.getOrCreateProcess(event.PID)
	}

	pt.UpdatePPID(proc, event)

	if pt.config.KubernetesMode {
		isCurrentUnderContainer := pt.containerTree.IsProcessUnderContainer(proc.PID, event.ContainerID, pt.getProcessMapAsRegularMap())
		if !isCurrentUnderContainer {
			shimPid, err := pt.containerTree.GetPidByContainerID(event.ContainerID)
			if err == nil {
				pt.updateProcessPPID(proc, shimPid)
			}
		}
	}

	if event.Comm != "" && proc.Comm != event.Comm {
		proc.Comm = event.Comm
	}
	if event.Pcomm != "" {
		proc.Pcomm = event.Pcomm
	}
	if event.Cmdline != "" {
		proc.Cmdline = event.Cmdline
	}
	if event.Uid != nil {
		proc.Uid = event.Uid
	}
	if event.Gid != nil {
		proc.Gid = event.Gid
	}
	if event.Cwd != "" {
		proc.Cwd = event.Cwd
	}
	if event.Path != "" {
		proc.Path = event.Path
	}
	if proc.ChildrenMap == nil {
		proc.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
	}
}

// handleExitEvent handles exit events - now uses delayed removal via integrated exit manager
func (pt *processTreeCreatorImpl) handleExitEvent(event feeder.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc := pt.processMap.Get(event.PID)
	if proc == nil {
		return
	}

	// Collect children for reparenting
	children := make([]*apitypes.Process, 0, len(proc.ChildrenMap))
	for _, child := range proc.ChildrenMap {
		if child != nil {
			children = append(children, child)
		}
	}

	// Add to pending exits for delayed cleanup
	pt.addPendingExit(event, children)
}

func (pt *processTreeCreatorImpl) getOrCreateProcess(pid uint32) *apitypes.Process {
	proc := pt.processMap.Get(pid)
	if proc != nil {
		return proc
	}
	proc = &apitypes.Process{PID: pid, ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	pt.processMap.Set(pid, proc)
	return proc
}

// linkProcessToParent ensures proc is added as a child to its parent (if PPID != 0)
func (pt *processTreeCreatorImpl) linkProcessToParent(proc *apitypes.Process) {
	if proc == nil || proc.PPID == 0 {
		return
	}

	// Prevent circular references: a process cannot be its own parent
	if proc.PPID == proc.PID {
		return
	}

	parent := pt.getOrCreateProcess(proc.PPID)
	if parent.ChildrenMap == nil {
		parent.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
	}
	key := apitypes.CommPID{Comm: proc.Comm, PID: proc.PID}
	parent.ChildrenMap[key] = proc
}

// updateProcessPPID safely updates a process's PPID by removing it from the old parent's
// children map and adding it to the new parent's children map
func (pt *processTreeCreatorImpl) updateProcessPPID(proc *apitypes.Process, newPPID uint32) {
	if proc == nil || proc.PPID == newPPID {
		return // No change needed
	}

	// Prevent circular references: a process cannot be its own parent
	if newPPID == proc.PID {
		return
	}

	// Prevent deeper circular references by checking if newPPID is a descendant of proc
	if pt.isDescendant(proc.PID, newPPID) {
		return
	}

	// Remove from old parent's children map
	if proc.PPID != 0 {
		if oldParent := pt.processMap.Get(proc.PPID); oldParent != nil && oldParent.ChildrenMap != nil {
			key := apitypes.CommPID{Comm: proc.Comm, PID: proc.PID}
			delete(oldParent.ChildrenMap, key)
		}
	}

	// Update PPID
	proc.PPID = newPPID

	// Add to new parent's children map
	pt.linkProcessToParent(proc)
}

// isDescendant checks if targetPID is a descendant of parentPID
func (pt *processTreeCreatorImpl) isDescendant(parentPID, targetPID uint32) bool {
	if parentPID == targetPID {
		return true
	}

	target := pt.processMap.Get(targetPID)
	if target == nil {
		return false
	}

	current := target
	for current != nil && current.PPID != 0 {
		if current.PPID == parentPID {
			return true
		}
		current = pt.processMap.Get(current.PPID)
	}

	return false
}

// getProcessMapAsRegularMap converts SafeMap to regular map for compatibility with existing interfaces
func (pt *processTreeCreatorImpl) getProcessMapAsRegularMap() map[uint32]*apitypes.Process {
	processMap := make(map[uint32]*apitypes.Process)
	pt.processMap.Range(func(pid uint32, proc *apitypes.Process) bool {
		processMap[pid] = proc
		return true
	})
	return processMap
}

// shallowCopyProcess creates a shallow copy of a process
// This is much faster and suitable for read-only access
func (pt *processTreeCreatorImpl) shallowCopyProcess(proc *apitypes.Process) *apitypes.Process {
	if proc == nil {
		return nil
	}
	copy := *proc
	// ChildrenMap points to the same map (shared reference)
	// This is safe for read-only access and much faster
	return &copy
}
