package processtreecreator

import (
	"fmt"
	"sync"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
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
	processMap       maps.SafeMap[uint32, *apitypes.Process] // PID -> Process
	exitedCache      *lru.Cache[uint32, time.Time]           // LRU cache for exited process hashes with TTL
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
		processMap:       maps.SafeMap[uint32, *apitypes.Process]{},
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
	for _, proc := range pt.processMap.Values() {
		if proc.PPID == 0 || pt.processMap.Get(proc.PPID) == nil {
			roots = append(roots, *pt.shallowCopyProcess(proc))
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

// GetProcessMapDeep returns a deep copy of the process map (slower but independent)
func (pt *processTreeCreatorImpl) GetProcessMapDeep() map[uint32]*apitypes.Process {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	processMap := make(map[uint32]*apitypes.Process)
	pt.processMap.Range(func(pid uint32, proc *apitypes.Process) bool {
		processMap[pid] = pt.deepCopyProcess(proc)
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

// Stop stops the process tree creator and cleanup resources
func (pt *processTreeCreatorImpl) Stop() {
	if pt.exitCleanup != nil {
		pt.exitCleanup.Stop()
	}
}

// TriggerExitCleanup triggers immediate exit cleanup (for testing purposes)
func (pt *processTreeCreatorImpl) TriggerExitCleanup() {
	if pt.exitCleanup != nil {
		// Acquire mutex before calling forceCleanup to prevent race conditions
		pt.mutex.Lock()
		pt.exitCleanup.forceCleanup()
		pt.mutex.Unlock()
	}
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

// GetContainerSubtreeAtomic performs container subtree operation atomically
// This ensures that the process map is not modified during the DeepCopy operation
func (pt *processTreeCreatorImpl) GetContainerSubtreeAtomic(containerTree interface{}, containerID string, targetPID uint32) (apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	// Type assert the container tree
	ct, ok := containerTree.(containerprocesstree.ContainerProcessTree)
	if !ok {
		return apitypes.Process{}, fmt.Errorf("invalid container tree type")
	}

	// Convert SafeMap to regular map for compatibility
	processMap := pt.getProcessMapAsRegularMap()

	// Perform the container subtree operation while holding the mutex
	return ct.GetContainerSubtree(containerID, targetPID, processMap)
}

// handleForkEvent handles fork events - only fills properties if they are empty or don't exist
func (pt *processTreeCreatorImpl) handleForkEvent(event feeder.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc := pt.processMap.Get(event.PID)

	// If process doesn't exist, check if it was previously exited
	if proc == nil {
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
		isPPIDUnderContainer := pt.containerTree != nil && event.PPID != 0 && pt.containerTree.IsPPIDUnderAnyContainerSubtree(event.PPID, pt.getProcessMapAsRegularMap())
		if isPPIDUnderContainer {
			// New PPID is under container subtree, update PPID and log the change
			logger.L().Info("Fork: Updating PPID to container subtree",
				helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("old_ppid", fmt.Sprintf("%d", proc.PPID)), helpers.String("new_ppid", fmt.Sprintf("%d", event.PPID)))
			pt.updateProcessPPID(proc, event.PPID)
		} else {
			// Check if process is already under any containerd-shim subtree
			isUnderContainer := pt.containerTree != nil && pt.containerTree.IsProcessUnderAnyContainerSubtree(event.PID, pt.getProcessMapAsRegularMap())
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

	proc := pt.processMap.Get(event.PID)

	// If process doesn't exist, check if it was previously exited
	if proc == nil {
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
		isPPIDUnderContainer := pt.containerTree != nil && event.PPID != 0 && pt.containerTree.IsPPIDUnderAnyContainerSubtree(event.PPID, pt.getProcessMapAsRegularMap())
		if isPPIDUnderContainer {
			// New PPID is under container subtree, update PPID and log the change
			logger.L().Info("ProcFS: Updating PPID to container subtree",
				helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("old_ppid", fmt.Sprintf("%d", proc.PPID)), helpers.String("new_ppid", fmt.Sprintf("%d", event.PPID)))
			pt.updateProcessPPID(proc, event.PPID)
		} else {
			// Check if process is already under any containerd-shim subtree
			isUnderContainer := pt.containerTree != nil && pt.containerTree.IsProcessUnderAnyContainerSubtree(event.PID, pt.getProcessMapAsRegularMap())
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

	proc := pt.processMap.Get(event.PID)

	if proc != nil {
		// Skip PPID update if new PPID is the same as current PPID (optimization)
		if event.PPID != proc.PPID {
			// New reparenting strategy:
			// 1. If new PPID is under container subtree, update regardless of current state
			// 2. Else if process is already under container, do nothing
			// 3. Else do standard PPID update logic

			// First check if new PPID is under any container subtree
			isPPIDUnderContainer := pt.containerTree != nil && event.PPID != 0 && pt.containerTree.IsPPIDUnderAnyContainerSubtree(event.PPID, pt.getProcessMapAsRegularMap())
			if isPPIDUnderContainer {
				// New PPID is under container subtree, update PPID and log the change
				logger.L().Info("Exec: Updating PPID to container subtree",
					helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("old_ppid", fmt.Sprintf("%d", proc.PPID)), helpers.String("new_ppid", fmt.Sprintf("%d", event.PPID)),
					helpers.String("Pcomm", event.Pcomm), helpers.String("comm", event.Comm), helpers.String("cmdline", event.Cmdline))
				pt.updateProcessPPID(proc, event.PPID)
			} else {
				// Check if process is already under any containerd-shim subtree
				isUnderContainer := pt.containerTree != nil && pt.containerTree.IsProcessUnderAnyContainerSubtree(event.PID, pt.getProcessMapAsRegularMap())
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
	proc := pt.processMap.Get(event.PID)
	if proc == nil {
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

	// Add to delayed cleanup for reparenting scenarios
	pt.exitCleanup.AddPendingExit(event, children)
	logger.L().Info("Exit: Added to delayed cleanup (has children)",
		helpers.String("pid", fmt.Sprintf("%d", event.PID)),
		helpers.String("children_count", fmt.Sprintf("%d", len(children))))
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
		logger.L().Warning("Process tree: Detected circular reference in PPID update, skipping",
			helpers.String("pid", fmt.Sprintf("%d", proc.PID)),
			helpers.String("new_ppid", fmt.Sprintf("%d", newPPID)),
			helpers.String("comm", proc.Comm))
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
