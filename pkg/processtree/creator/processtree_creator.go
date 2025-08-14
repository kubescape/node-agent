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
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/kubescape/node-agent/pkg/processtree/reparenting"
)	

type processTreeCreatorImpl struct {
	processMap            maps.SafeMap[uint32, *apitypes.Process] // PID -> Process
	containerTree         containerprocesstree.ContainerProcessTree
	reparentingStrategies reparenting.ReparentingStrategies
	mutex                 sync.RWMutex // Protects process tree modifications
	config                config.Config

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
		processMap:            maps.SafeMap[uint32, *apitypes.Process]{},
		reparentingStrategies: reparentingLogic,
		containerTree:         containerTree,
		pendingExits:          make(map[uint32]*pendingExit),
		config:                config,
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

func (pt *processTreeCreatorImpl) FeedEvent(event conversion.ProcessEvent) {
	switch event.Type {
	case conversion.ForkEvent:
		pt.handleForkEvent(event)
	case conversion.ProcfsEvent:
		pt.handleProcfsEvent(event)
	case conversion.ExecEvent:
		pt.handleExecEvent(event)
	case conversion.ExitEvent:
		pt.handleExitEvent(event)
	}
}

func (pt *processTreeCreatorImpl) GetRootTree() ([]apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	// Find root processes (those whose parent is not in the map or PPID==0)
	roots := []apitypes.Process{}
	for _, proc := range pt.processMap.Values() {
		_, ok := pt.processMap.Load(proc.PPID)
		if proc.PPID == 0 || !ok {
			roots = append(roots, *proc)
		}
	}
	return roots, nil
}

func (pt *processTreeCreatorImpl) GetProcessMap() *maps.SafeMap[uint32, *apitypes.Process] {
	return &pt.processMap
}

func (pt *processTreeCreatorImpl) GetProcessNode(pid int) (*apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	proc, ok := pt.processMap.Load(uint32(pid))
	if !ok {
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

	return ct.GetPidBranch(containerID, targetPID, &pt.processMap)
}

// UpdatePPID handles PPID updates using the new reparenting strategy
func (pt *processTreeCreatorImpl) UpdatePPID(proc *apitypes.Process, event conversion.ProcessEvent) {
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
		IsNewPPIDUnderContainer := pt.containerTree.IsProcessUnderContainer(event.PPID, event.ContainerID, &pt.processMap)
		if IsNewPPIDUnderContainer {
			pt.updateProcessPPID(proc, event.PPID)
		} else {
			isCurrentUnderContainer := pt.containerTree.IsProcessUnderContainer(proc.PID, event.ContainerID, &pt.processMap)
			if !isCurrentUnderContainer {
				pt.updateProcessPPID(proc, event.PPID)
			}
		}
	}
}

// handleForkEvent handles fork events - only fills properties if they are empty or don't exist
func (pt *processTreeCreatorImpl) handleForkEvent(event conversion.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc, ok := pt.processMap.Load(event.PID)
	if !ok {
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

func (pt *processTreeCreatorImpl) handleProcfsEvent(event conversion.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc, ok := pt.processMap.Load(event.PID)
	if !ok {
		proc = pt.getOrCreateProcess(event.PID)
	}

	if event.Comm != "" {
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

func (pt *processTreeCreatorImpl) handleExecEvent(event conversion.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc, ok := pt.processMap.Load(event.PID)
	if !ok {
		proc = pt.getOrCreateProcess(event.PID)
	}

	pt.UpdatePPID(proc, event)

	if pt.config.KubernetesMode {
		isCurrentUnderContainer := pt.containerTree.IsProcessUnderContainer(proc.PID, event.ContainerID, &pt.processMap)
		if !isCurrentUnderContainer {
			shimPid, err := pt.containerTree.GetPidByContainerID(event.ContainerID)
			if err == nil {
				pt.updateProcessPPID(proc, shimPid)
			}
		}
	}

	if event.Comm != "" {
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
func (pt *processTreeCreatorImpl) handleExitEvent(event conversion.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc, ok := pt.processMap.Load(event.PID)
	if !ok {
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
	proc, ok := pt.processMap.Load(pid)
	if ok {
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
	key := apitypes.CommPID{PID: proc.PID}
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
		if oldParent, ok := pt.processMap.Load(proc.PPID); ok && oldParent.ChildrenMap != nil {
			key := apitypes.CommPID{PID: proc.PID}
			if _, ok := oldParent.ChildrenMap[key]; ok {
				delete(oldParent.ChildrenMap, key)
			} else {
				logger.L().Warning("updateProcessPPID: process not found in old parent's children map", helpers.String("pid", fmt.Sprintf("%d", proc.PID)))
			}
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

	target, ok := pt.processMap.Load(targetPID)
	if !ok {
		return false
	}

	current := target
	for current != nil && current.PPID != 0 {
		if current.PPID == parentPID {
			return true
		}
		current, ok = pt.processMap.Load(current.PPID)
		if !ok {
			break
		}
	}

	return false
}

func (pt *processTreeCreatorImpl) shallowCopyProcess(proc *apitypes.Process) *apitypes.Process {
	if proc == nil {
		return nil
	}
	copy := *proc
	return &copy
}
