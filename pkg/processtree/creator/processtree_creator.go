package processtreecreator

import (
	"fmt"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	lru "github.com/hashicorp/golang-lru/v2"
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
	// LRU cache to track processes under containerd-shim: key is "pid:startTimeNs"
	containerdShimCache *lru.Cache[string, bool]
}

func NewProcessTreeCreator(containerTree containerprocesstree.ContainerProcessTree) ProcessTreeCreator {
	// Create reparenting logic
	reparentingLogic, err := reparenting.NewReparentingLogic()
	if err != nil {
		logger.L().Warning("Failed to create reparenting logic, using fallback", helpers.Error(err))
		reparentingLogic = nil
	}

	// Create LRU cache for containerd-shim processes (10,000 entries)
	containerdShimCache, err := lru.New[string, bool](10000)
	if err != nil {
		logger.L().Warning("Failed to create containerd-shim cache, using fallback", helpers.Error(err))
		containerdShimCache = nil
	}

	return &processTreeCreatorImpl{
		processMap:          maps.SafeMap[uint32, *apitypes.Process]{},
		reparentingLogic:    reparentingLogic,
		containerTree:       containerTree,
		containerdShimCache: containerdShimCache,
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
			roots = append(roots, *pt.shallowCopyProcess(proc))
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

// Stop stops the process tree creator and cleanup resources
func (pt *processTreeCreatorImpl) Stop() {
	// Clean up LRU cache
	if pt.containerdShimCache != nil {
		pt.containerdShimCache.Purge()
	}
}

// handleForkEvent handles fork events - only fills properties if they are empty or don't exist
func (pt *processTreeCreatorImpl) handleForkEvent(event feeder.ProcessEvent) {
	proc := pt.processMap.Get(event.PID)

	// If process doesn't exist, create it
	if proc == nil {
		proc = pt.getOrCreateProcess(event.PID)
		logger.L().Info("PROC - Fork: Creating new process",
			helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("start_time_ns", fmt.Sprintf("%d", event.StartTimeNs)),
			helpers.String("ppid", fmt.Sprintf("%d", event.PPID)), helpers.String("comm", event.Comm), helpers.String("pcomm", event.Pcomm),
			helpers.String("cmdline", event.Cmdline))
	}

	// Skip PPID update if new PPID is the same as current PPID (optimization)
	if event.PPID != proc.PPID {
		// Use new reparenting strategy
		if pt.shouldUpdatePPID(event.PID, event.StartTimeNs) {
			pt.updateProcessPPID(proc, event.PPID)
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
	proc := pt.processMap.Get(event.PID)

	// If process doesn't exist, create it
	if proc == nil {
		logger.L().Info("PROC - ProcFS: Creating new process",
			helpers.String("pid", fmt.Sprintf("%d", event.PID)),
			helpers.String("start_time_ns", fmt.Sprintf("%d", event.StartTimeNs)), helpers.String("ppid", fmt.Sprintf("%d", event.PPID)),
			helpers.String("comm", event.Comm), helpers.String("pcomm", event.Pcomm), helpers.String("cmdline", event.Cmdline))

		proc = pt.getOrCreateProcess(event.PID)
	}

	// Use new reparenting strategy
	if event.PPID != proc.PPID {
		if pt.shouldUpdatePPID(event.PID, event.StartTimeNs) {
			pt.updateProcessPPID(proc, event.PPID)
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
	proc := pt.processMap.Get(event.PID)

	if proc != nil {
		// Skip PPID update if new PPID is the same as current PPID (optimization)
		if event.PPID != proc.PPID {
			// Use new reparenting strategy
			if pt.shouldUpdatePPID(event.PID, event.StartTimeNs) {
				pt.updateProcessPPID(proc, event.PPID)
			}
		}
	} else {
		// If process doesn't exist, create it (should be rare)
		proc = pt.getOrCreateProcess(event.PID)
		logger.L().Info("PROC - Exec: Creating new process (no prior fork event)",
			helpers.String("pid", fmt.Sprintf("%d", event.PID)), helpers.String("start_time_ns", fmt.Sprintf("%d", event.StartTimeNs)), helpers.String("ppid", fmt.Sprintf("%d", event.PPID)))
	}

	logger.L().Info("PROC - Exec: info",
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

// handleExitEvent handles exit events - immediate removal and reparenting
func (pt *processTreeCreatorImpl) handleExitEvent(event feeder.ProcessEvent) {
	proc := pt.processMap.Get(event.PID)
	if proc == nil {
		return // Process doesn't exist, nothing to clean up
	}

	// Collect children for reparenting
	children := make([]*apitypes.Process, 0, len(proc.ChildrenMap))
	for _, child := range proc.ChildrenMap {
		if child != nil {
			children = append(children, child)
		}
	}

	// Handle reparenting of orphaned children immediately
	if len(children) > 0 {
		if pt.reparentingLogic != nil {
			// Use the reparenting logic to determine the new parent
			result := pt.reparentingLogic.HandleProcessExit(event.PID, children, pt.containerTree, pt.getProcessMapAsRegularMap())

			logger.L().Info("PROC - Exit: Immediate reparenting",
				helpers.String("pid", fmt.Sprintf("%d", event.PID)),
				helpers.String("strategy", result.Strategy),
				helpers.String("new_parent_pid", fmt.Sprintf("%d", result.NewParentPID)),
				helpers.String("verified", fmt.Sprintf("%t", result.Verified)),
				helpers.String("children_count", fmt.Sprintf("%d", len(children))))

			// Update children's PPID to the new parent and link them
			for _, child := range children {
				if child != nil {
					child.PPID = result.NewParentPID
					pt.linkProcessToParent(child)
				}
			}
		} else {
			// Fallback to init process (PID 1) if reparenting logic is not available
			logger.L().Warning("Exit: Reparenting logic not available, using fallback to init",
				helpers.String("pid", fmt.Sprintf("%d", event.PID)))

			for _, child := range children {
				if child != nil {
					child.PPID = 1 // Adopted by init process
					pt.linkProcessToParent(child)
				}
			}
		}
	}

	// Remove from parent's children list
	if proc.PPID != 0 {
		if parent := pt.processMap.Get(proc.PPID); parent != nil {
			delete(parent.ChildrenMap, apitypes.CommPID{Comm: proc.Comm, PID: event.PID})
		}
	}

	// Remove the process from the map immediately
	pt.processMap.Delete(event.PID)

	logger.L().Info("PROC - Exit: Removed process immediately",
		helpers.String("pid", fmt.Sprintf("%d", event.PID)),
		helpers.String("start_time_ns", fmt.Sprintf("%d", event.StartTimeNs)),
		helpers.String("children_count", fmt.Sprintf("%d", len(children))))
}

func (pt *processTreeCreatorImpl) getOrCreateProcess(pid uint32) *apitypes.Process {
	proc := pt.processMap.Get(pid)
	if proc != nil {
		return proc
	}
	proc = &apitypes.Process{PID: pid, ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	pt.processMap.Set(pid, proc)
	pt.linkProcessToParent(proc)
	return proc
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

func (pt *processTreeCreatorImpl) updateProcessPPID(proc *apitypes.Process, newPPID uint32) {
	if proc == nil || proc.PPID == newPPID {
		return
	}

	if proc.PPID != 0 {
		if oldParent := pt.processMap.Get(proc.PPID); oldParent != nil && oldParent.ChildrenMap != nil {
			key := apitypes.CommPID{Comm: proc.Comm, PID: proc.PID}
			delete(oldParent.ChildrenMap, key)
		}
	}

	proc.PPID = newPPID

	pt.linkProcessToParent(proc)

	isUnderContainer := pt.containerTree.IsProcessUnderAnyContainerSubtree(proc.PID, pt.getProcessMapAsRegularMap())
	if isUnderContainer {
		logger.L().Info("PROC - Under container", helpers.String("pid", fmt.Sprintf("%d", proc.PID)), helpers.String("new_ppid", fmt.Sprintf("%d", newPPID)))
	}
}

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

func (pt *processTreeCreatorImpl) shouldUpdatePPID(pid uint32, startTimeNs uint64) bool {
	cacheKey := pt.getCacheKey(pid, startTimeNs)
	if cached, exists := pt.containerdShimCache.Get(cacheKey); exists {
		return cached
	}

	isUnderContainer := pt.containerTree.IsProcessUnderAnyContainerSubtree(pid, pt.getProcessMapAsRegularMap())

	if isUnderContainer {
		pt.containerdShimCache.Add(cacheKey, isUnderContainer)
	}

	if !isUnderContainer {
		logger.L().Info("PROC - shouldUpdatePPID", helpers.String("pid", fmt.Sprintf("%d", pid)), helpers.String("isUnderContainer", fmt.Sprintf("%t", isUnderContainer)))
	} else {
		logger.L().Info("PROC - Not under container", helpers.String("pid", fmt.Sprintf("%d", pid)))
	}

	return !isUnderContainer
}

func (pt *processTreeCreatorImpl) getProcessMapAsRegularMap() map[uint32]*apitypes.Process {
	processMap := make(map[uint32]*apitypes.Process)
	pt.processMap.Range(func(pid uint32, proc *apitypes.Process) bool {
		processMap[pid] = proc
		return true
	})
	return processMap
}

func (pt *processTreeCreatorImpl) getCacheKey(pid uint32, startTimeNs uint64) string {
	return fmt.Sprintf("%d:%d", pid, startTimeNs)
}
