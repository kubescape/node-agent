package processtreecreator

import (
	"sync"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/kubescape/node-agent/pkg/processtree/utils"
)

type processTreeCreatorImpl struct {
	mutex       sync.RWMutex
	processMap  map[uint32]*apitypes.Process  // PID -> Process
	exitedCache *lru.Cache[uint32, time.Time] // LRU cache for exited process hashes with TTL
}

func NewProcessTreeCreator() ProcessTreeCreator {
	// Create LRU cache for exited processes with size 1000
	exitedCache, err := lru.New[uint32, time.Time](1000)
	if err != nil {
		// Fallback to nil cache if creation fails
		exitedCache = nil
	}

	return &processTreeCreatorImpl{
		processMap:  make(map[uint32]*apitypes.Process),
		exitedCache: exitedCache,
	}
}

func (pt *processTreeCreatorImpl) FeedEvent(event feeder.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

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

func (pt *processTreeCreatorImpl) GetNodeTree() ([]apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	// Find root processes (those whose parent is not in the map or PPID==0)
	roots := []apitypes.Process{}
	for _, proc := range pt.processMap {
		if proc.PPID == 0 || pt.processMap[proc.PPID] == nil {
			roots = append(roots, *pt.deepCopyProcess(proc))
		}
	}
	return roots, nil
}

func (pt *processTreeCreatorImpl) GetProcessNode(pid int) (*apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	proc, ok := pt.processMap[uint32(pid)]
	if !ok {
		return nil, nil
	}
	return pt.deepCopyProcess(proc), nil
}

// handleForkEvent handles fork events - only fills properties if they are empty or don't exist
func (pt *processTreeCreatorImpl) handleForkEvent(event feeder.ProcessEvent) {
	proc, exists := pt.processMap[event.PID]

	// If process doesn't exist, check if it was previously exited
	if !exists {
		processHash := utils.HashTaskID(event.PID, event.StartTimeNs)
		if pt.isProcessExited(processHash) {
			return // Don't create a new process that has already exited
		}
		// Create new process if it wasn't exited
		proc = &apitypes.Process{PID: event.PID, ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
		pt.processMap[event.PID] = proc
	}

	// Only set fields if they are empty or don't exist (enrichment)
	if proc.PPID == 0 {
		proc.PPID = event.PPID
	}
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

	// Link to parent
	if event.PPID != 0 {
		parent := pt.getOrCreateProcess(event.PPID)
		if parent.ChildrenMap == nil {
			parent.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
		}
		parent.ChildrenMap[apitypes.CommPID{Comm: event.Comm, PID: event.PID}] = proc
	}
}

// handleProcfsEvent handles procfs events - overrides when existing values are empty or don't exist
func (pt *processTreeCreatorImpl) handleProcfsEvent(event feeder.ProcessEvent) {
	proc, exists := pt.processMap[event.PID]

	// If process doesn't exist, check if it was previously exited
	if !exists {
		processHash := utils.HashTaskID(event.PID, event.StartTimeNs)
		if pt.isProcessExited(processHash) {
			return // Don't create a new process that has already exited
		}
		// Create new process if it wasn't exited
		proc = &apitypes.Process{PID: event.PID, ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
		pt.processMap[event.PID] = proc
	}

	// Override fields if the new value is non-empty and the existing value is empty or default (enrichment)
	if event.PPID != 0 && proc.PPID == 0 {
		proc.PPID = event.PPID
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

	// Link to parent
	if event.PPID != 0 {
		parent := pt.getOrCreateProcess(event.PPID)
		if parent.ChildrenMap == nil {
			parent.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
		}
		parent.ChildrenMap[apitypes.CommPID{Comm: event.Comm, PID: event.PID}] = proc
	}
}

// handleExecEvent handles exec events - always overrides when it has values
func (pt *processTreeCreatorImpl) handleExecEvent(event feeder.ProcessEvent) {
	proc, exists := pt.processMap[event.PID]

	// If process doesn't exist, check if it was previously exited
	if !exists {
		processHash := utils.HashTaskID(event.PID, event.StartTimeNs)
		if pt.isProcessExited(processHash) {
			return // Don't create a new process that has already exited
		}
		// Create new process if it wasn't exited
		proc = pt.getOrCreateProcess(event.PID)
	}

	// Always override with new values if they are provided (enrichment)
	if event.PPID != 0 {
		proc.PPID = event.PPID
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

// handleExitEvent handles exit events - removes process and updates orphaned children
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

	// Remove from parent's children list first
	if proc.PPID != 0 {
		if parent, parentExists := pt.processMap[proc.PPID]; parentExists {
			delete(parent.ChildrenMap, apitypes.CommPID{Comm: proc.Comm, PID: event.PID})
		}
	}

	// Update children's PPID to 1 (init process) since they become orphaned
	for childCommPID, child := range proc.ChildrenMap {
		if child != nil {
			child.PPID = 1 // Adopted by init process

			// Add child to init process (PID 1) if it exists
			if initProc, initExists := pt.processMap[1]; initExists {
				if initProc.ChildrenMap == nil {
					initProc.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
				}
				initProc.ChildrenMap[childCommPID] = child
			}
		}
	}

	// Only remove the exiting process, not its descendants
	delete(pt.processMap, event.PID)
}

func (pt *processTreeCreatorImpl) getOrCreateProcess(pid uint32) *apitypes.Process {
	if proc, ok := pt.processMap[pid]; ok {
		return proc
	}
	proc := &apitypes.Process{PID: pid, ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	pt.processMap[pid] = proc
	return proc
}

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
