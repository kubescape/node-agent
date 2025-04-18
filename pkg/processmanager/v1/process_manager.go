package processmanager

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/prometheus/procfs"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	cleanupInterval = 1 * time.Minute
	maxTreeDepth    = 50
	runCCommPrefix  = "runc:["
)

type ProcessManager struct {
	containerIdToShimPid maps.SafeMap[string, apitypes.CommPID]
	processTree          maps.SafeMap[apitypes.CommPID, *apitypes.Process]
	// For testing purposes we allow to override the function that gets process info from /proc.
	getProcessFromProc func(pid int) (*apitypes.Process, error)
}

func CreateProcessManager(ctx context.Context) *ProcessManager {
	pm := &ProcessManager{
		getProcessFromProc: getProcessFromProc,
	}
	go pm.startCleanupRoutine(ctx)
	return pm
}

// PopulateInitialProcesses scans the /proc filesystem to build the initial process tree
// for all registered container shim processes. It establishes parent-child relationships
// between processes and adds them to the process tree if they are descendants of a shim.
func (p *ProcessManager) PopulateInitialProcesses() error {
	if len(p.containerIdToShimPid.Keys()) == 0 {
		return nil
	}

	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return fmt.Errorf("failed to open procfs: %w", err)
	}

	procs, err := fs.AllProcs()
	if err != nil {
		return fmt.Errorf("failed to read all procs: %w", err)
	}

	tempProcesses := make(map[apitypes.CommPID]*apitypes.Process, len(procs))
	shimPIDs := make(map[apitypes.CommPID]struct{})

	p.containerIdToShimPid.Range(func(_ string, shimPID apitypes.CommPID) bool {
		shimPIDs[shimPID] = struct{}{}
		return true
	})

	// First collect all processes
	for _, proc := range procs {
		if process, err := p.getProcessFromProc(proc.PID); err == nil {
			tempProcesses[apitypes.CommPID{Comm: process.Comm, PID: process.PID}] = process
		}
	}

	// Then build relationships and add to tree
	for pid, process := range tempProcesses {
		ppid := apitypes.CommPID{Comm: process.Pcomm, PID: process.PPID}
		if p.isDescendantOfShim(pid, ppid, shimPIDs, tempProcesses) {
			if parent, exists := tempProcesses[ppid]; exists {
				parent.ChildrenMap[pid] = process
			}
			p.processTree.Set(pid, process)
		}
	}

	return nil
}

// isDescendantOfShim checks if a process with the given PID is a descendant of any
// registered shim process. It traverses the process tree upwards until it either finds
// a shim process or reaches the maximum tree depth to prevent infinite loops.
func (p *ProcessManager) isDescendantOfShim(pid apitypes.CommPID, ppid apitypes.CommPID, shimPIDs map[apitypes.CommPID]struct{}, processes map[apitypes.CommPID]*apitypes.Process) bool {
	visited := make(map[apitypes.CommPID]bool)
	currentPID := pid
	for depth := 0; depth < maxTreeDepth; depth++ {
		if currentPID.PID == 0 || visited[currentPID] {
			return false
		}
		visited[currentPID] = true

		if _, isShim := shimPIDs[ppid]; isShim {
			return true
		}

		process, exists := processes[ppid]
		if !exists {
			return false
		}
		currentPID = ppid
		ppid = apitypes.CommPID{Comm: process.Pcomm, PID: process.PPID}
	}
	return false
}

// ContainerCallback handles container lifecycle events (creation and removal).
// For new containers, it identifies the container's shim process and adds it to the tracking system.
// For removed containers, it cleans up the associated processes from the process tree.
func (p *ProcessManager) ContainerCallback(notif containercollection.PubSubEvent) {
	containerID := notif.Container.Runtime.BasicRuntimeMetadata.ContainerID

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		containerPID := notif.Container.ContainerPid()
		if process, err := p.getProcessFromProc(int(containerPID)); err == nil {
			shimPID := apitypes.CommPID{Comm: process.Pcomm, PID: process.PPID}
			p.containerIdToShimPid.Set(containerID, shimPID)
			p.addProcess(process)
		} else {
			logger.L().Warning("ProcessManager.ContainerCallback - failed to get container process info",
				helpers.String("containerID", containerID),
				helpers.Error(err))
		}

	case containercollection.EventTypeRemoveContainer:
		if shimPID, exists := p.containerIdToShimPid.Load(containerID); exists {
			p.removeProcessesUnderShim(shimPID)
			p.containerIdToShimPid.Delete(containerID)
		}
	}
}

// removeProcessesUnderShim removes all processes that are descendants of the specified
// shim process PID from the process tree. This is typically called when a container
// is being removed.
func (p *ProcessManager) removeProcessesUnderShim(shimPID apitypes.CommPID) {
	var pidsToRemove []apitypes.CommPID

	// CAREFUL this is RLocking the map, do not call other methods that Lock the map
	p.processTree.Range(func(pid apitypes.CommPID, _ *apitypes.Process) bool {
		currentPID := pid
		visited := make(map[apitypes.CommPID]bool)

		for currentPID.PID != 0 && !visited[currentPID] {
			visited[currentPID] = true
			if proc, exists := p.processTree.Load(currentPID); exists { // this is not a deadlock since Range and Load use RLock
				ppid := apitypes.CommPID{Comm: proc.Pcomm, PID: proc.PPID}
				if ppid == shimPID {
					pidsToRemove = append(pidsToRemove, pid)
					break
				}
				currentPID = ppid
			} else {
				break
			}
		}
		return true
	})

	// Remove in reverse order to handle parent-child relationships
	for i := len(pidsToRemove) - 1; i >= 0; i-- {
		p.removeProcess(pidsToRemove[i])
	}
}

// addProcess adds or updates a process in the process tree and maintains the
// parent-child relationships between processes. If the process already exists
// with a different parent, it updates the relationships accordingly.
func (p *ProcessManager) addProcess(process *apitypes.Process) {
	// First, check if the process already exists and has a different parent
	pid := apitypes.CommPID{Comm: process.Comm, PID: process.PID}
	if existingProc, exists := p.processTree.Load(pid); exists && existingProc.PPID != process.PPID {
		// Remove from old parent's children list
		if oldParent, exists := p.processTree.Load(apitypes.CommPID{Comm: existingProc.Pcomm, PID: existingProc.PPID}); exists {
			delete(oldParent.ChildrenMap, pid)
		}
	}

	// Update the process in the tree
	p.processTree.Set(pid, process)

	// Update new parent's children list
	if parent, exists := p.processTree.Load(apitypes.CommPID{Comm: process.Pcomm, PID: process.PPID}); exists {
		parent.ChildrenMap[pid] = process
	}
}

// removeProcess removes a process from the process tree and updates the parent-child
// relationships. Children of the removed process are reassigned to their grandparent
// to maintain the process hierarchy.
func (p *ProcessManager) removeProcess(pid apitypes.CommPID) {
	if process, exists := p.processTree.Load(pid); exists {
		if parent, exists := p.processTree.Load(apitypes.CommPID{Comm: process.Pcomm, PID: process.PPID}); exists {
			delete(parent.ChildrenMap, pid)
		}

		for _, child := range process.ChildrenMap {
			if childProcess, exists := p.processTree.Load(apitypes.CommPID{Comm: child.Comm, PID: child.PID}); exists {
				childProcess.PPID = process.PPID
				childProcess.Pcomm = process.Pcomm
				p.addProcess(childProcess)
			}
		}

		p.processTree.Delete(pid)
	}
}

// GetProcessTreeForPID retrieves the process tree for a specific PID within a container.
// It returns the process and all its ancestors up to the container's shim process.
// If the process is not in the tree, it attempts to fetch it from /proc.
func (p *ProcessManager) GetProcessTreeForPID(containerID string, pid apitypes.CommPID) (*apitypes.Process, error) {
	if !p.containerIdToShimPid.Has(containerID) {
		return nil, fmt.Errorf("container ID %s not found", containerID)
	}

	result, exists := p.processTree.Load(pid)
	if !exists {
		logger.L().Debug("ProcessManager - process not found in tree, fetching from /proc",
			helpers.Interface("pid", pid))
		process, err := p.getProcessFromProc(int(pid.PID))
		if err != nil {
			return nil, fmt.Errorf("process %d not found: %v", pid.PID, err)
		}

		if strings.HasPrefix(process.Comm, runCCommPrefix) {
			return nil, fmt.Errorf("process %d is a runc process, not supported", pid.PID)
		}
		p.addProcess(process)
		result = process
	}

	currentPID := apitypes.CommPID{Comm: result.Pcomm, PID: result.PPID}
	seen := make(map[apitypes.CommPID]bool)

	for currentPID != p.containerIdToShimPid.Get(containerID) && currentPID.PID != 0 {
		if seen[currentPID] {
			break
		}
		seen[currentPID] = true

		if parent, exists := p.processTree.Load(currentPID); exists {
			parentCopy := parent
			parentCopy.ChildrenMap = map[apitypes.CommPID]*apitypes.Process{apitypes.CommPID{Comm: result.Comm, PID: result.PID}: result}
			result = parentCopy
			currentPID = apitypes.CommPID{Comm: parent.Pcomm, PID: parent.PPID}
		} else {
			break
		}
	}

	// If the process is runc, try to fetch the real process info.
	// Intentionally we are doing this only once the process is asked for to avoid unnecessary calls to /proc and give time for the process to be created.
	if strings.HasPrefix(result.Comm, runCCommPrefix) {
		if resolvedProcess, err := p.resolveRuncProcess(result); err == nil {
			result = resolvedProcess
		} else {
			logger.L().Debug("ProcessManager - failed to resolve runc process",
				helpers.Int("pid", int(result.PID)),
				helpers.String("comm", result.Comm),
				helpers.Error(err))
		}
	}

	return result, nil
}

func (p *ProcessManager) resolveRuncProcess(process *apitypes.Process) (*apitypes.Process, error) {
	err := backoff.Retry(func() error {
		resolvedProcess, err := p.getProcessFromProc(int(process.PID))
		if err != nil {
			return err
		}

		if strings.HasPrefix(resolvedProcess.Comm, runCCommPrefix) {
			return fmt.Errorf("runc process not resolved yet")
		}

		children := process.ChildrenMap
		upperLayer := process.UpperLayer
		process = resolvedProcess
		process.ChildrenMap = children
		process.UpperLayer = upperLayer

		// Update the process in the tree
		p.processTree.Set(apitypes.CommPID{Comm: process.Comm, PID: process.PID}, process)
		return nil
	}, backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(50*time.Millisecond),
		backoff.WithMaxInterval(100*time.Millisecond),
		backoff.WithMaxElapsedTime(2*time.Second),
	))

	if err != nil {
		return nil, fmt.Errorf("failed to resolve runc process: %v", err)
	}

	return process, nil
}

// ReportEvent handles process execution events from the system.
// It specifically processes execve events to track new process creations
// and updates the process tree accordingly.
func (p *ProcessManager) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	if eventType != utils.ExecveEventType {
		return
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return
	}

	process := apitypes.Process{
		PID:         execEvent.Pid,
		PPID:        execEvent.Ppid,
		Comm:        execEvent.Comm,
		Uid:         &execEvent.Uid,
		Gid:         &execEvent.Gid,
		Hardlink:    execEvent.ExePath,
		UpperLayer:  &execEvent.UpperLayer,
		Path:        execEvent.ExePath,
		Cwd:         execEvent.Cwd,
		Pcomm:       execEvent.Pcomm,
		Cmdline:     fmt.Sprintf("%s %s", utils.GetExecPathFromEvent(&execEvent.Event), strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	p.addProcess(&process)
}

// startCleanupRoutine starts a goroutine that periodically runs the cleanup
// function to remove dead processes from the process tree. It continues until
// the context is cancelled.
// TODO: Register eBPF tracer to get process exit events and remove dead processes immediately.
func (p *ProcessManager) startCleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()
		case <-ctx.Done():
			return
		}
	}
}

// cleanup removes dead processes from the process tree by checking if each
// process in the tree is still alive in the system.
func (p *ProcessManager) cleanup() {
	deadPids := make(map[apitypes.CommPID]bool)
	// CAREFUL this is RLocking the map, do not call other methods that Lock the map
	p.processTree.Range(func(pid apitypes.CommPID, _ *apitypes.Process) bool {
		if !isProcessAlive(int(pid.PID)) {
			deadPids[pid] = true
		}
		return true
	})

	for pid := range deadPids {
		logger.L().Debug("ProcessManager - removing dead process", helpers.Interface("pid", pid))
		p.removeProcess(pid)
	}
}

// getProcessFromProc retrieves process information from the /proc filesystem
// for a given PID. It collects various process attributes such as command line,
// working directory, and user/group IDs.
func getProcessFromProc(pid int) (*apitypes.Process, error) {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get process info: %v", err)
	}

	stat, err := utils.GetProcessStat(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get process stat: %v", err)
	}

	var uid, gid uint32
	if status, err := proc.NewStatus(); err == nil {
		// UIDs and GIDs have a fixed length of 4 elements
		uid = uint32(status.UIDs[1])
		gid = uint32(status.GIDs[1])
	}

	cmdline, _ := proc.CmdLine()
	if len(cmdline) == 0 {
		cmdline = []string{stat.Comm}
	}

	cwd, _ := proc.Cwd()
	path, _ := proc.Executable()
	pcomm := func() string {
		if stat.PPID <= 0 {
			return ""
		}

		parentProc, err := procfs.NewProc(stat.PPID)
		if err != nil {
			return ""
		}

		parentStat, err := parentProc.Stat()
		if err != nil {
			return ""
		}

		return parentStat.Comm
	}()

	return &apitypes.Process{
		PID:         uint32(pid),
		PPID:        uint32(stat.PPID),
		Comm:        stat.Comm,
		Pcomm:       pcomm,
		Uid:         &uid,
		Gid:         &gid,
		Cmdline:     strings.Join(cmdline, " "),
		Cwd:         cwd,
		Path:        path,
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}, nil
}

// isProcessAlive checks if a process with the given PID is still running
// by attempting to read its information from the /proc filesystem.
func isProcessAlive(pid int) bool {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return false
	}
	_, err = proc.Stat()
	return err == nil
}
