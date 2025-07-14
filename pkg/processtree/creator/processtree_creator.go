package processtreecreator

import (
	"fmt"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/kubescape/node-agent/pkg/processtree/reparenting"
)

type processTreeCreatorImpl struct {
	processMap       maps.SafeMap[uint32, *apitypes.Process] // PID -> Process
	containerTree    containerprocesstree.ContainerProcessTree
	reparentingLogic reparenting.ReparentingLogic
}

func NewProcessTreeCreator(containerTree containerprocesstree.ContainerProcessTree) ProcessTreeCreator {
	// Create reparenting logic
	reparentingLogic, err := reparenting.NewReparentingLogic()
	if err != nil {
		logger.L().Warning("Failed to create reparenting logic, using fallback", helpers.Error(err))
		reparentingLogic = nil
	}

	return &processTreeCreatorImpl{
		processMap:       maps.SafeMap[uint32, *apitypes.Process]{},
		reparentingLogic: reparentingLogic,
		containerTree:    containerTree,
	}
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
	// Convert SafeMap to regular map for compatibility
	processMap := make(map[uint32]*apitypes.Process)
	pt.processMap.Range(func(pid uint32, proc *apitypes.Process) bool {
		processMap[pid] = proc
		return true
	})
	return processMap
}

func (pt *processTreeCreatorImpl) GetProcessNode(pid int) (*apitypes.Process, error) {
	proc := pt.processMap.Get(uint32(pid))
	if proc == nil {
		return nil, nil
	}
	return pt.shallowCopyProcess(proc), nil
}

// GetContainerSubtree performs container subtree operation (no longer needs to be atomic)
func (pt *processTreeCreatorImpl) GetContainerSubtree(containerTree interface{}, containerID string, targetPID uint32) (apitypes.Process, error) {
	// Type assert the container tree
	ct, ok := containerTree.(containerprocesstree.ContainerProcessTree)
	if !ok {
		return apitypes.Process{}, fmt.Errorf("invalid container tree type")
	}

	// Convert SafeMap to regular map for compatibility
	processMap := pt.getProcessMapAsRegularMap()

	// Perform the container subtree operation
	return ct.GetContainerSubtree(containerID, targetPID, processMap)
}

// UpdatePPID handles PPID updates using the new reparenting strategy
func (pt *processTreeCreatorImpl) UpdatePPID(proc *apitypes.Process, event feeder.ProcessEvent) {
	if event.PPID != proc.PPID && event.PPID != 0 {
		// New reparenting strategy:
		// 1. If new PPID is under container subtree, update regardless of current state
		// 2. Else if process is already under container, do nothing
		// 3. Else do standard PPID update logic

		// First check if new PPID is under any container subtree
		IsNewPPIDUnderContainer := pt.containerTree.IsProcessUnderAnyContainerSubtree(event.PPID, pt.getProcessMapAsRegularMap())
		if IsNewPPIDUnderContainer {
			pt.updateProcessPPID(proc, event.PPID)
		} else {
			isCurrentUnderContainer := pt.containerTree.IsProcessUnderAnyContainerSubtree(proc.PID, pt.getProcessMapAsRegularMap())
			if !isCurrentUnderContainer {
				pt.updateProcessPPID(proc, event.PPID)
			}
		}
	}
}

// handleForkEvent handles fork events - only fills properties if they are empty or don't exist
func (pt *processTreeCreatorImpl) handleForkEvent(event feeder.ProcessEvent) {
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
	proc := pt.processMap.Get(event.PID)

	if proc == nil {
		proc = pt.getOrCreateProcess(event.PID)
	}

	pt.UpdatePPID(proc, event)

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
	proc := pt.processMap.Get(event.PID)
	if proc == nil {
		proc = pt.getOrCreateProcess(event.PID)
	}

	pt.UpdatePPID(proc, event)

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

// handleExitEvent handles exit events - immediate removal and reparenting
func (pt *processTreeCreatorImpl) handleExitEvent(event feeder.ProcessEvent) {
	proc := pt.processMap.Get(event.PID)
	if proc == nil {
		return
	}

	children := make([]*apitypes.Process, 0, len(proc.ChildrenMap))
	for _, child := range proc.ChildrenMap {
		if child != nil {
			children = append(children, child)
		}
	}

	if len(children) > 0 {
		result := pt.reparentingLogic.HandleProcessExit(event.PID, children, pt.containerTree, pt.getProcessMapAsRegularMap())
		for _, child := range children {
			if child != nil {
				child.PPID = result.NewParentPID
				pt.linkProcessToParent(child)
			}
		}
	} else {
		for _, child := range children {
			if child != nil {
				child.PPID = 1
				pt.linkProcessToParent(child)
			}
		}
	}

	if proc.PPID != 0 {
		if parent := pt.processMap.Get(proc.PPID); parent != nil {
			delete(parent.ChildrenMap, apitypes.CommPID{Comm: proc.Comm, PID: event.PID})
		}
	}

	pt.processMap.Delete(event.PID)
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
		logger.L().Warning("Process tree: Detected circular reference, skipping parent link",
			helpers.String("pid", fmt.Sprintf("%d", proc.PID)),
			helpers.String("ppid", fmt.Sprintf("%d", proc.PPID)),
			helpers.String("comm", proc.Comm))
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
