package processtreecreator

import (
	"fmt"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/kubescape/node-agent/pkg/processtree/reparenting"
)

type processTreeCreatorImpl struct {
	processMap            maps.SafeMap[uint32, *armotypes.Process] // PID -> Process
	containerTree         containerprocesstree.ContainerProcessTree
	reparentingStrategies reparenting.ReparentingStrategies
	mutex                 sync.RWMutex // Protects process tree modifications
	config                config.Config

	// Exit manager fields
	pendingExits map[uint32]*pendingExit // PID -> pending exit

	// exitCleanupStopChan is the loop's stop signal while it is armed, and nil once
	// stopped, which is what lets startExitManager bring the loop back up. It is
	// an intent flag, not a liveness flag: it is non-nil before the goroutine has
	// been scheduled, and nil while a signalled loop is still finishing its current
	// iteration. Do not read it as "the loop is running".
	//
	// Every access in non-test code is under exitCleanupMutex, and NOT under
	// pt.mutex: the tree lock is held across performExitCleanup, so reusing it for
	// lifecycle transitions would couple shutdown to tree contention. Tests read
	// the field directly, which is safe only because those reads are sequenced
	// after Start/Stop returns and the loop never touches the field — it receives
	// the channel as an argument.
	exitCleanupStopChan chan struct{}
	exitCleanupMutex    sync.Mutex

	// pidStartTimeNs maps a live pid to its creation time in nanoseconds since
	// boot, sourced EXCLUSIVELY from /proc/<pid>/stat field 22 (never from
	// fork/exec/exit event timestamps, which are epoch wall-clock — a different
	// clock domain). This side map is the SOLE process-identity time source; the
	// wall-clock Process.StartTime stamped on tree nodes is display-only and
	// inherits btime's whole-second skew. Guarded by pt.mutex. Entries are
	// deleted in exitByPid together with the tree node.
	pidStartTimeNs map[uint32]uint64

	// readStartTime fetches a pid's boot-relative start time and display-only
	// wall time from /proc on demand, so a node created by a fork or exec event
	// does not wait up to a full scan interval for its identity. Returns zeros
	// when the process is already gone. Injectable for tests.
	readStartTime func(pid uint32) (uint64, time.Time)

	// nowBootNs reads CLOCK_BOOTTIME in nanoseconds, the same clock domain as
	// pidStartTimeNs, so an exit's arrival can be compared against a node's
	// recorded creation time. Injectable for tests; read through pt.bootTimeNs(),
	// which tolerates a nil hook by returning 0 ("unknown").
	nowBootNs func() uint64
}

func NewProcessTreeCreator(containerTree containerprocesstree.ContainerProcessTree, config config.Config) ProcessTreeCreator {
	// Create reparenting logic
	reparentingLogic, err := reparenting.NewReparentingLogic()
	if err != nil {
		logger.L().Warning("Failed to create reparenting logic, using fallback", helpers.Error(err))
		reparentingLogic = nil
	}

	creator := &processTreeCreatorImpl{
		processMap:            maps.SafeMap[uint32, *armotypes.Process]{},
		reparentingStrategies: reparentingLogic,
		containerTree:         containerTree,
		pendingExits:          make(map[uint32]*pendingExit),
		pidStartTimeNs:        make(map[uint32]uint64),
		readStartTime:         newProcfsStartTimeReader(),
		nowBootNs:             readBootTimeNs,
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

func (pt *processTreeCreatorImpl) GetRootTree() ([]armotypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	// Find root processes (those whose parent is not in the map or PPID==0)
	roots := []armotypes.Process{}
	for _, proc := range pt.processMap.Values() {
		_, ok := pt.processMap.Load(proc.PPID)
		if proc.PPID == 0 || !ok {
			roots = append(roots, *proc)
		}
	}
	return roots, nil
}

func (pt *processTreeCreatorImpl) GetProcessMap() *maps.SafeMap[uint32, *armotypes.Process] {
	return &pt.processMap
}

func (pt *processTreeCreatorImpl) GetProcessNode(pid int) (*armotypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	proc, ok := pt.processMap.Load(uint32(pid))
	if !ok {
		return nil, nil
	}
	return pt.shallowCopyProcess(proc), nil
}

// GetProcessBootTimeNs returns the pid's creation time as nanoseconds since boot
// (CLOCK_BOOTTIME), or 0 when unknown — the process has not been seen by the
// /proc scan or an on-demand read, or it has already exited. Procfs-sourced
// only; see pidStartTimeNs for the identity contract.
func (pt *processTreeCreatorImpl) GetProcessBootTimeNs(pid uint32) uint64 {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	return pt.pidStartTimeNs[pid]
}

// GetPidBranch performs container branch operation (no longer needs to be atomic)
func (pt *processTreeCreatorImpl) GetPidBranch(containerTree interface{}, containerID string, targetPID uint32) (armotypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	// Type assert the container tree
	ct, ok := containerTree.(containerprocesstree.ContainerProcessTree)
	if !ok {
		return armotypes.Process{}, fmt.Errorf("invalid container tree type")
	}

	return ct.GetPidBranch(containerID, targetPID, &pt.processMap)
}

// UpdatePPID handles PPID updates using the new reparenting strategy
func (pt *processTreeCreatorImpl) UpdatePPID(proc *armotypes.Process, event conversion.ProcessEvent) {
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

// ensureStartTime gives a fork/exec-created node its process identity without
// waiting up to a full scan interval for the periodic /proc sweep — short-lived
// processes are the population most exposed to pid reuse, and they are exactly
// the ones the scan misses.
//
// One read per node creation, never per event: an exec on a node whose entry
// already exists must not re-read, because creation time cannot change on exec.
//
// event.StartTimeNs is deliberately ignored. For fork and exec events it is the
// event's wall-clock timestamp — epoch nanoseconds, not boot-relative, and
// stamping the event rather than process creation. Only the procfs read may
// populate the side map. A failed read leaves zero, never a guess.
//
// Must be called with pt.mutex held.
func (pt *processTreeCreatorImpl) ensureStartTime(proc *armotypes.Process, pid uint32) {
	if _, known := pt.pidStartTimeNs[pid]; known {
		return
	}
	ns, wall := pt.readStartTime(pid)
	pt.applyStartTime(proc, pid, ns, wall)
}

// applyStartTime stores an already-read start time. Split out from
// ensureStartTime so the fork path can perform its /proc read before taking
// pt.mutex: fork is the highest-volume event path and always reads (the
// recycled-pid guard drops any stale entry), so reading under the tree-wide
// write lock would serialise a file read into the hot path for every alert
// type. Exec keeps the read inside ensureStartTime, where the
// skip-when-already-known check makes it conditional.
//
// A zero ns means the read failed — leave the pre-existing zero, never guess.
//
// Must be called with pt.mutex held.
func (pt *processTreeCreatorImpl) applyStartTime(proc *armotypes.Process, pid uint32, ns uint64, wall time.Time) {
	if ns == 0 {
		return
	}
	pt.pidStartTimeNs[pid] = ns
	if !wall.IsZero() {
		proc.StartTime = wall
	}
}

// handleForkEvent handles fork events - only fills properties if they are empty or don't exist
func (pt *processTreeCreatorImpl) handleForkEvent(event conversion.ProcessEvent) {
	// Read the start time BEFORE taking the tree lock. A fork always needs it —
	// the pid is newborn, and the guard below drops any stale value — so this is
	// the same number of reads as doing it under the lock, with none of them
	// holding it. Widening the gap between event and read only widens an
	// already-accepted race: if the pid is recycled in between, the value read
	// belongs to the current incarnation, which the reuse hardening detects.
	startTimeNs, startTimeWall := pt.readStartTime(event.PID)

	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	// A fork's pid is newborn, so a pending exit on it can only belong to a dead
	// predecessor whose pid the kernel recycled. Retire that predecessor — node,
	// children and pending entry — before touching the node below.
	pt.retireRecycledPredecessor(event.PID)

	proc, ok := pt.processMap.Load(event.PID)
	if !ok {
		proc = pt.getOrCreateProcess(event.PID)
	} else if _, exited := pt.pendingExits[event.PID]; exited {
		// Reached only when retireRecycledPredecessor could not tear the node
		// down: exitByPid bails out when reparenting fails, leaving both the node
		// and the pending entry in place. Fall back to the narrower start-time
		// guard — drop BOTH halves of the stale value, identity and display, so
		// they cannot disagree, and let applyStartTime restamp them below.
		//
		// Gated on a pending exit rather than on the node merely existing: an
		// existing node alone only means some other path created it first, and
		// wiping on that weaker signal would discard a good scan-recorded value
		// whenever the on-demand read then fails.
		//
		// On this path the node keeps the dead process's comm, cmdline and path.
		// That is deliberate: a failed reparent must fall through to exactly
		// today's behaviour rather than invent a partial teardown.
		delete(pt.pidStartTimeNs, event.PID)
		proc.StartTime = time.Time{}
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

	pt.applyStartTime(proc, event.PID, startTimeNs, startTimeWall)

	if proc.ChildrenMap == nil {
		proc.ChildrenMap = make(map[armotypes.CommPID]*armotypes.Process)
	}
}

func (pt *processTreeCreatorImpl) handleProcfsEvent(event conversion.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	proc, ok := pt.processMap.Load(event.PID)
	if !ok {
		if pt.config.KubernetesMode && event.ContainerID == armotypes.HostContainerID { // If we are in Kubernetes mode and the container ID is "host", don't create the process.
			return
		}

		proc = pt.getOrCreateProcess(event.PID)
	}

	// Pid-reuse guard (L3): two procfs readings of the same process always yield
	// the identical starttime ticks, so a different NON-ZERO value proves the
	// kernel recycled this pid. No tolerance is needed, and none should be added.
	//
	// Never merge across incarnations. The overwrite-only-if-non-empty block below
	// preserves any field the new process does not report, so the dead process's
	// Cwd, Path and friends would otherwise survive into it — a node describing
	// two processes at once. Tear the stale node down instead and rebuild from this
	// event. A pending exit for the dead incarnation is consumed here too, which
	// disarms its delayed deletion.
	//
	// The children are reparented by the teardown. Most belonged to the dead
	// process, but not necessarily all: this fires up to a scan interval after the
	// recycle, so the successor may already have forked. Detaching a live child is
	// a worse-in-one-direction trade against retaining a dead parent, and it
	// self-corrects on the child's next scan — see the doc's observable changes.
	//
	// A zero on either side proves nothing and falls through to today's merge, so
	// this never fires for a pid the side map has no prior value for. That is also
	// why a pending exit must NOT be the signal on this path: /proc lists zombies,
	// so the same incarnation can legitimately have one.
	if event.StartTimeNs != 0 {
		if prev := pt.pidStartTimeNs[event.PID]; prev != 0 && prev != event.StartTimeNs {
			if _, removed := pt.removeProcessNode(event.PID); removed {
				delete(pt.pendingExits, event.PID)

				// Re-apply the host-process policy the absent-node path above
				// enforces. Rebuilding unconditionally would let a host procfs
				// event materialise a node that a first sighting would refuse.
				if pt.config.KubernetesMode && event.ContainerID == armotypes.HostContainerID {
					return
				}

				proc = pt.getOrCreateProcess(event.PID)
			}
			// If the teardown failed, fall through and merge as before.
		}
	}

	if event.PPID != 0 {
		pt.UpdatePPID(proc, event)
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

	// Start time from /proc/<pid>/stat field 22. The boot-relative value is the
	// identity source and lives only in the side map; the wall-clock value is
	// stamped on the node for display and must never be compared for identity.
	if event.StartTimeNs != 0 {
		pt.pidStartTimeNs[event.PID] = event.StartTimeNs
		if !event.StartTimeWall.IsZero() {
			proc.StartTime = event.StartTimeWall
		}
	}

	if proc.ChildrenMap == nil {
		proc.ChildrenMap = make(map[armotypes.CommPID]*armotypes.Process)
	}
}

func (pt *processTreeCreatorImpl) handleExecEvent(event conversion.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	// An exec proves a live process holds this pid, so a pending exit on it
	// belongs to a recycled predecessor. Exec already overwrites comm, cmdline and
	// path, so the visible identity would self-correct — but the predecessor's
	// delayed exit would still delete this live process's node, and its children
	// would still be inherited. Retire it for those two reasons.
	pt.retireRecycledPredecessor(event.PID)

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

	pt.ensureStartTime(proc, event.PID)

	if proc.ChildrenMap == nil {
		proc.ChildrenMap = make(map[armotypes.CommPID]*armotypes.Process)
	}
}

// handleExitEvent handles exit events - now uses delayed removal via integrated exit manager
func (pt *processTreeCreatorImpl) handleExitEvent(event conversion.ProcessEvent) {
	// Read the boot clock BEFORE taking the tree lock. unix.ClockGettime is a raw
	// syscall — x/sys does not route it through the vDSO the way the runtime does
	// for time.Now — and exits are about as frequent as forks, thousands per second
	// on a busy node. Holding pt.mutex across it would put syscall latency on the
	// tree-wide write lock that every alert type reads through, which is the same
	// mistake the fork path's start-time read avoids, for the same reason.
	arrivalBootNs := pt.bootTimeNs()

	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	pt.addPendingExit(event, arrivalBootNs)
}

func (pt *processTreeCreatorImpl) getOrCreateProcess(pid uint32) *armotypes.Process {
	proc, ok := pt.processMap.Load(pid)
	if ok {
		return proc
	}
	proc = &armotypes.Process{PID: pid, ChildrenMap: make(map[armotypes.CommPID]*armotypes.Process)}
	pt.processMap.Set(pid, proc)

	return proc
}

// linkProcessToParent ensures proc is added as a child to its parent (if PPID != 0)
func (pt *processTreeCreatorImpl) linkProcessToParent(proc *armotypes.Process) {
	if proc == nil || proc.PPID == 0 {
		return
	}

	// Prevent circular references: a process cannot be its own parent
	if proc.PPID == proc.PID {
		return
	}

	parent := pt.getOrCreateProcess(proc.PPID)
	if parent.ChildrenMap == nil {
		parent.ChildrenMap = make(map[armotypes.CommPID]*armotypes.Process)
	}
	key := armotypes.CommPID{PID: proc.PID}
	parent.ChildrenMap[key] = proc
}

// updateProcessPPID safely updates a process's PPID by removing it from the old parent's
// children map and adding it to the new parent's children map
func (pt *processTreeCreatorImpl) updateProcessPPID(proc *armotypes.Process, newPPID uint32) {
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
			key := armotypes.CommPID{PID: proc.PID}
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

func (pt *processTreeCreatorImpl) shallowCopyProcess(proc *armotypes.Process) *armotypes.Process {
	if proc == nil {
		return nil
	}
	process := *proc
	return &process
}
