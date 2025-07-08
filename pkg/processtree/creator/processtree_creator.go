package processtreecreator

import (
	"fmt"
	"sync"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/kubescape/node-agent/pkg/processtree/reparenting"
	"github.com/kubescape/node-agent/pkg/processtree/utils"
)

type processTreeCreatorImpl struct {
	mutex            sync.RWMutex
	processMap       map[uint32]*apitypes.Process  // PID -> Process
	exitedCache      *lru.Cache[uint32, time.Time] // LRU cache for exited process hashes with TTL
	containerTree    containerprocesstree.ContainerProcessTree
	reparentingLogic reparenting.ReparentingLogic
	exitCleanup      *ExitCleanupManager
}

func NewProcessTreeCreator(containerTree containerprocesstree.ContainerProcessTree) ProcessTreeCreator {
	// Create LRU cache for exited processes with size 1000
	exitedCache, err := lru.New[uint32, time.Time](1000)
	if err != nil {
		// Fallback to nil cache if creation fails
		exitedCache = nil
	}

	// Create reparenting logic
	reparentingLogic, err := reparenting.NewReparentingLogic()
	if err != nil {
		logger.L().Warning("Failed to create reparenting logic, using fallback", helpers.Error(err))
		reparentingLogic = nil
	}

	creator := &processTreeCreatorImpl{
		processMap:       make(map[uint32]*apitypes.Process),
		exitedCache:      exitedCache,
		reparentingLogic: reparentingLogic,
		containerTree:    containerTree,
	}

	// Create and start the exit cleanup manager
	creator.exitCleanup = NewExitCleanupManager(creator)
	creator.exitCleanup.Start()

	return creator
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
	for _, proc := range pt.processMap {
		if proc.PPID == 0 || pt.processMap[proc.PPID] == nil {
			roots = append(roots, *pt.shallowCopyProcess(proc))
		}
	}
	return roots, nil
}

func (pt *processTreeCreatorImpl) GetProcessMap() map[uint32]*apitypes.Process {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	// Return the original map since callers only read from it and proper locking is in place
	// This avoids unnecessary copying and improves performance
	return pt.processMap
}

// GetProcessMapDeep returns a deep copy of the process map (slower but independent)
func (pt *processTreeCreatorImpl) GetProcessMapDeep() map[uint32]*apitypes.Process {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	processMap := make(map[uint32]*apitypes.Process)
	for pid, proc := range pt.processMap {
		processMap[pid] = pt.deepCopyProcess(proc)
	}
	return processMap
}

func (pt *processTreeCreatorImpl) GetProcessNode(pid int) (*apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	proc, ok := pt.processMap[uint32(pid)]
	if !ok {
		return nil, nil
	}
	return pt.shallowCopyProcess(proc), nil
}

// Stop stops the process tree creator and cleanup resources
func (pt *processTreeCreatorImpl) Stop() {
	if pt.exitCleanup != nil {
		pt.exitCleanup.Stop()
	}
}

// TriggerExitCleanup triggers immediate exit cleanup (for testing purposes)
func (pt *processTreeCreatorImpl) TriggerExitCleanup() {
	if pt.exitCleanup != nil {
		pt.exitCleanup.forceCleanup()
	}
}

// handleForkEvent handles fork events - only fills properties if they are empty or don't exist
func (pt *processTreeCreatorImpl) handleForkEvent(event feeder.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc, exists := pt.processMap[event.PID]

	// If process doesn't exist, check if it was previously exited
	if !exists {
		processHash := utils.HashTaskID(event.PID, event.StartTimeNs)
		if pt.isProcessExited(processHash) {
			return // Don't create a new process that has already exited
		}
		// Create new process if it wasn't exited
		proc = pt.getOrCreateProcess(event.PID)
		logger.L().Info("Fork: Creating new process",
			helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("start_time_ns", fmt.Sprintf("%d", event.StartTimeNs)),
			helpers.String("ppid", fmt.Sprintf("%d", event.PPID)), helpers.String("comm", event.Comm), helpers.String("pcomm", event.Pcomm),
			helpers.String("cmdline", event.Cmdline))
	}

	// Skip PPID update if new PPID is the same as current PPID (optimization)
	if event.PPID != proc.PPID {
		// New reparenting strategy:
		// 1. If new PPID is under container subtree, update regardless of current state
		// 2. Else if process is already under container, do nothing
		// 3. Else do standard PPID update logic

		// First check if new PPID is under any container subtree
		isPPIDUnderContainer := pt.containerTree != nil && event.PPID != 0 && pt.containerTree.IsPPIDUnderAnyContainerSubtree(event.PPID, pt.processMap)
		if isPPIDUnderContainer {
			// New PPID is under container subtree, update PPID and log the change
			logger.L().Info("Fork: Updating PPID to container subtree",
				helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("old_ppid", fmt.Sprintf("%d", proc.PPID)), helpers.String("new_ppid", fmt.Sprintf("%d", event.PPID)))
			pt.updateProcessPPID(proc, event.PPID)
		} else {
			// Check if process is already under any containerd-shim subtree
			isUnderContainer := pt.containerTree != nil && pt.containerTree.IsProcessUnderAnyContainerSubtree(event.PID, pt.processMap)
			if isUnderContainer {
				// Process is already under container subtree, do nothing
				logger.L().Debug("Fork: Process already under container subtree, no PPID update",
					helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("current_ppid", fmt.Sprintf("%d", proc.PPID)), helpers.String("new_ppid", fmt.Sprintf("%d", event.PPID)))
			} else {
				// Standard PPID update logic for non-container processes (only if empty for fork events)
				if proc.PPID == 0 {
					pt.updateProcessPPID(proc, event.PPID)
				}
			}
		}
	}

	// Only set fields if they are empty or don't exist (enrichment)
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

// handleProcfsEvent handles procfs events - overrides when existing values are empty or don't exist
func (pt *processTreeCreatorImpl) handleProcfsEvent(event feeder.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc, exists := pt.processMap[event.PID]

	// If process doesn't exist, check if it was previously exited
	if !exists {
		logger.L().Info("ProcFS: Creating new process",
			helpers.String("pid", fmt.Sprintf("%d", event.PID)),
			helpers.String("start_time_ns", fmt.Sprintf("%d", event.StartTimeNs)), helpers.String("ppid", fmt.Sprintf("%d", event.PPID)),
			helpers.String("comm", event.Comm), helpers.String("pcomm", event.Pcomm), helpers.String("cmdline", event.Cmdline))

		processHash := utils.HashTaskID(event.PID, event.StartTimeNs)
		if pt.isProcessExited(processHash) {
			logger.L().Info("ProcFS: Process has already exited",
				helpers.String("pid", fmt.Sprintf("%d", event.PID)),
				helpers.String("start_time_ns", fmt.Sprintf("%d", event.StartTimeNs)),
				helpers.String("comm", event.Comm), helpers.String("pcomm", event.Pcomm), helpers.String("cmdline", event.Cmdline))
			return // Don't create a new process that has already exited
		}
		// Create new process if it wasn't exited
		proc = pt.getOrCreateProcess(event.PID)
	}

	// Skip PPID update if new PPID is the same as current PPID (optimization)
	if event.PPID != proc.PPID {
		// New reparenting strategy:
		// 1. If new PPID is under container subtree, update regardless of current state
		// 2. Else if process is already under container, do nothing
		// 3. Else do standard PPID update logic

		// First check if new PPID is under any container subtree
		isPPIDUnderContainer := pt.containerTree != nil && event.PPID != 0 && pt.containerTree.IsPPIDUnderAnyContainerSubtree(event.PPID, pt.processMap)
		if isPPIDUnderContainer {
			// New PPID is under container subtree, update PPID and log the change
			logger.L().Info("ProcFS: Updating PPID to container subtree",
				helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("old_ppid", fmt.Sprintf("%d", proc.PPID)), helpers.String("new_ppid", fmt.Sprintf("%d", event.PPID)))
			pt.updateProcessPPID(proc, event.PPID)
		} else {
			// Check if process is already under any containerd-shim subtree
			isUnderContainer := pt.containerTree != nil && pt.containerTree.IsProcessUnderAnyContainerSubtree(event.PID, pt.processMap)
			if isUnderContainer {
				// Process is already under container subtree, do nothing
				logger.L().Debug("ProcFS: Process already under container subtree, no PPID update",
					helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("current_ppid", fmt.Sprintf("%d", proc.PPID)), helpers.String("new_ppid", fmt.Sprintf("%d", event.PPID)))
			} else {
				// Standard PPID update logic for non-container processes
				if event.PPID != 0 && proc.PPID == 0 {
					logger.L().Info("ProcFS: Setting PPID",
						helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("start_time_ns", fmt.Sprintf("%d", event.StartTimeNs)), helpers.String("ppid", fmt.Sprintf("%d", event.PPID)))
					pt.updateProcessPPID(proc, event.PPID)
				}
			}
		}
	}

	// Override fields if the new value is non-empty and the existing value is empty or default (enrichment)
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

// handleExecEvent handles exec events - always enriches the existing process node if present, never creates a duplicate
func (pt *processTreeCreatorImpl) handleExecEvent(event feeder.ProcessEvent) {
	// Always lock for write, as we may update the process node
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc, exists := pt.processMap[event.PID]

	if exists {
		// Skip PPID update if new PPID is the same as current PPID (optimization)
		if event.PPID != proc.PPID {
			// New reparenting strategy:
			// 1. If new PPID is under container subtree, update regardless of current state
			// 2. Else if process is already under container, do nothing
			// 3. Else do standard PPID update logic

			// First check if new PPID is under any container subtree
			isPPIDUnderContainer := pt.containerTree != nil && event.PPID != 0 && pt.containerTree.IsPPIDUnderAnyContainerSubtree(event.PPID, pt.processMap)
			if isPPIDUnderContainer {
				// New PPID is under container subtree, update PPID and log the change
				logger.L().Info("Exec: Updating PPID to container subtree",
					helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("old_ppid", fmt.Sprintf("%d", proc.PPID)), helpers.String("new_ppid", fmt.Sprintf("%d", event.PPID)),
					helpers.String("Pcomm", event.Pcomm), helpers.String("comm", event.Comm), helpers.String("cmdline", event.Cmdline))
				pt.updateProcessPPID(proc, event.PPID)
			} else {
				// Check if process is already under any containerd-shim subtree
				isUnderContainer := pt.containerTree != nil && pt.containerTree.IsProcessUnderAnyContainerSubtree(event.PID, pt.processMap)
				if isUnderContainer {
					// Process is already under container subtree, do nothings
					logger.L().Debug("Exec: Process already under container subtree, no PPID update",
						helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("current_ppid", fmt.Sprintf("%d", proc.PPID)), helpers.String("new_ppid", fmt.Sprintf("%d", event.PPID)))
				} else {
					// Standard PPID update logic for non-container processes
					if event.PPID != 0 {
						logger.L().Info("Exec: Setting PPID",
							helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("start_time_ns", fmt.Sprintf("%d", event.StartTimeNs)),
							helpers.String("ppid", fmt.Sprintf("%d", event.PPID)), helpers.String("Pcomm", event.Pcomm),
							helpers.String("comm", event.Comm), helpers.String("cmdline", event.Cmdline))
						pt.updateProcessPPID(proc, event.PPID)
					}
				}
			}
		}
	} else {
		// If process doesn't exist, check if it was previously exited
		processHash := utils.HashTaskID(event.PID, event.StartTimeNs)
		if pt.isProcessExited(processHash) {
			logger.L().Info("Exec: Process has already exited",
				helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("start_time_ns", fmt.Sprintf("%d", event.StartTimeNs)), helpers.String("ppid", fmt.Sprintf("%d", event.PPID)))
			return // Don't create a new process that has already exited
		}
		// Create new process if it wasn't exited (should be rare)
		proc = pt.getOrCreateProcess(event.PID)
		logger.L().Info("Exec: Creating new process (no prior fork event)",
			helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("start_time_ns", fmt.Sprintf("%d", event.StartTimeNs)), helpers.String("ppid", fmt.Sprintf("%d", event.PPID)))
	}
	logger.L().Info("Exec: info",
		helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("old_ppid", fmt.Sprintf("%d", proc.PPID)),
		helpers.String("new_ppid", fmt.Sprintf("%d", event.PPID)), helpers.String("comm", event.Comm), helpers.String("pcomm", event.Pcomm))
	// Fill all fields from exec event (PPID is already handled above)
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

// handleExitEvent handles exit events - immediate removal for processes without children, delayed cleanup for reparenting
// Caller must hold pt.mutex
func (pt *processTreeCreatorImpl) handleExitEvent(event feeder.ProcessEvent) {
	proc, exists := pt.processMap[event.PID]
	if !exists {
		return // Process doesn't exist, nothing to clean up
	}

	// Create unique hash for this process instance and mark it as exited
	processHash := utils.HashTaskID(event.PID, event.StartTimeNs)
	if pt.exitedCache != nil {
		pt.exitedCache.Add(processHash, time.Now())
	}

	// Collect children for reparenting
	children := make([]*apitypes.Process, 0, len(proc.ChildrenMap))
	for _, child := range proc.ChildrenMap {
		if child != nil {
			children = append(children, child)
		}
	}

	// Hybrid approach: immediate cleanup for processes without children, delayed for processes with children
	if len(children) == 0 {
		// Immediate cleanup for processes without children
		pt.removeProcessImmediately(event.PID)
		logger.L().Info("Exit: Immediate cleanup (no children)",
			helpers.String("pid", fmt.Sprintf("%d", event.PID)))
	} else {
		// Add to delayed cleanup for reparenting scenarios
		pt.exitCleanup.AddPendingExit(event, children)
		logger.L().Info("Exit: Added to delayed cleanup (has children)",
			helpers.String("pid", fmt.Sprintf("%d", event.PID)),
			helpers.String("children_count", fmt.Sprintf("%d", len(children))))
	}
}

// removeProcessImmediately removes a process immediately without reparenting logic
// Caller must hold pt.mutex
func (pt *processTreeCreatorImpl) removeProcessImmediately(pid uint32) {
	proc, exists := pt.processMap[pid]
	if !exists {
		return
	}

	// Remove from parent's children list
	if proc.PPID != 0 {
		if parent, parentExists := pt.processMap[proc.PPID]; parentExists {
			delete(parent.ChildrenMap, apitypes.CommPID{Comm: proc.Comm, PID: pid})
		}
	}

	// Remove the process from the map
	delete(pt.processMap, pid)

	logger.L().Info("Exit: Removed process immediately",
		helpers.String("pid", fmt.Sprintf("%d", pid)))
}

func (pt *processTreeCreatorImpl) getOrCreateProcess(pid uint32) *apitypes.Process {
	if proc, ok := pt.processMap[pid]; ok {
		return proc
	}
	proc := &apitypes.Process{PID: pid, ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	pt.processMap[pid] = proc
	return proc
}

// deepCopyProcess creates a deep copy of a process with all its children
// This is used when we need a complete independent copy
func (pt *processTreeCreatorImpl) deepCopyProcess(proc *apitypes.Process) *apitypes.Process {
	if proc == nil {
		return nil
	}
	copy := *proc
	copy.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
	for k, v := range proc.ChildrenMap {
		copy.ChildrenMap[k] = pt.deepCopyProcess(v)
	}
	return &copy
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

// isProcessExited checks if a process hash has been marked as exited
// and cleans up expired entries (older than 1 hour)
func (pt *processTreeCreatorImpl) isProcessExited(processHash uint32) bool {
	if pt.exitedCache == nil {
		return false
	}

	if exitTime, exists := pt.exitedCache.Get(processHash); exists {
		// Check if the entry has expired (1 hour TTL)
		if time.Since(exitTime) > time.Hour {
			pt.exitedCache.Remove(processHash)
			return false
		}
		return true
	}
	return false
}

// linkProcessToParent ensures proc is added as a child to its parent (if PPID != 0)
func (pt *processTreeCreatorImpl) linkProcessToParent(proc *apitypes.Process) {
	if proc == nil || proc.PPID == 0 {
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

	// Remove from old parent's children map
	if proc.PPID != 0 {
		if oldParent, exists := pt.processMap[proc.PPID]; exists && oldParent.ChildrenMap != nil {
			key := apitypes.CommPID{Comm: proc.Comm, PID: proc.PID}
			delete(oldParent.ChildrenMap, key)
		}
	}

	// Update PPID
	proc.PPID = newPPID

	// Add to new parent's children map
	pt.linkProcessToParent(proc)
}
