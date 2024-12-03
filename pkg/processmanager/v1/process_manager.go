package processmanager

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/prometheus/procfs"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	cleanupInterval = 1 * time.Minute
	maxTreeDepth    = 50
)

type ProcessManager struct {
	containerIdToShimPid maps.SafeMap[string, uint32]
	processTree          maps.SafeMap[uint32, apitypes.Process]
	// For testing purposes we allow to override the function that gets process info from /proc.
	getProcessFromProc func(pid int) (apitypes.Process, error)
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

	tempProcesses := make(map[uint32]apitypes.Process, len(procs))
	shimPIDs := make(map[uint32]struct{})

	p.containerIdToShimPid.Range(func(_ string, shimPID uint32) bool {
		shimPIDs[shimPID] = struct{}{}
		return true
	})

	// First collect all processes
	for _, proc := range procs {
		if process, err := p.getProcessFromProc(proc.PID); err == nil {
			tempProcesses[process.PID] = process
		}
	}

	// Then build relationships and add to tree
	for pid, process := range tempProcesses {
		if p.isDescendantOfShim(pid, process.PPID, shimPIDs, tempProcesses) {
			if parent, exists := tempProcesses[process.PPID]; exists {
				parent.Children = append(parent.Children, process)
				tempProcesses[process.PPID] = parent
			}
			p.processTree.Set(pid, process)
		}
	}

	return nil
}

// isDescendantOfShim checks if a process with the given PID is a descendant of any
// registered shim process. It traverses the process tree upwards until it either finds
// a shim process or reaches the maximum tree depth to prevent infinite loops.
func (p *ProcessManager) isDescendantOfShim(pid uint32, ppid uint32, shimPIDs map[uint32]struct{}, processes map[uint32]apitypes.Process) bool {
	visited := make(map[uint32]bool)
	currentPID := pid
	for depth := 0; depth < maxTreeDepth; depth++ {
		if currentPID == 0 || visited[currentPID] {
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
		ppid = process.PPID
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
		containerPID := uint32(notif.Container.ContainerPid())
		if process, err := p.getProcessFromProc(int(containerPID)); err == nil {
			shimPID := process.PPID
			p.containerIdToShimPid.Set(containerID, shimPID)
			p.addProcess(process)
		} else {
			logger.L().Warning("Failed to get container process info",
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
func (p *ProcessManager) removeProcessesUnderShim(shimPID uint32) {
	var pidsToRemove []uint32

	p.processTree.Range(func(pid uint32, process apitypes.Process) bool {
		currentPID := pid
		visited := make(map[uint32]bool)

		for currentPID != 0 && !visited[currentPID] {
			visited[currentPID] = true
			if proc, exists := p.processTree.Load(currentPID); exists {
				if proc.PPID == shimPID {
					pidsToRemove = append(pidsToRemove, pid)
					break
				}
				currentPID = proc.PPID
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
func (p *ProcessManager) addProcess(process apitypes.Process) {
	// First, check if the process already exists and has a different parent
	if existingProc, exists := p.processTree.Load(process.PID); exists && existingProc.PPID != process.PPID {
		// Remove from old parent's children list
		if oldParent, exists := p.processTree.Load(existingProc.PPID); exists {
			newChildren := make([]apitypes.Process, 0, len(oldParent.Children))
			for _, child := range oldParent.Children {
				if child.PID != process.PID {
					newChildren = append(newChildren, child)
				}
			}
			oldParent.Children = newChildren
			p.processTree.Set(oldParent.PID, oldParent)
		}
	}

	// Update the process in the tree
	p.processTree.Set(process.PID, process)

	// Update new parent's children list
	if parent, exists := p.processTree.Load(process.PPID); exists {
		newChildren := make([]apitypes.Process, 0, len(parent.Children)+1)
		hasProcess := false
		for _, child := range parent.Children {
			if child.PID == process.PID {
				hasProcess = true
				newChildren = append(newChildren, process)
			} else {
				newChildren = append(newChildren, child)
			}
		}
		if !hasProcess {
			newChildren = append(newChildren, process)
		}
		parent.Children = newChildren
		p.processTree.Set(parent.PID, parent)
	}
}

// removeProcess removes a process from the process tree and updates the parent-child
// relationships. Children of the removed process are reassigned to their grandparent
// to maintain the process hierarchy.
func (p *ProcessManager) removeProcess(pid uint32) {
	if process, exists := p.processTree.Load(pid); exists {
		if parent, exists := p.processTree.Load(process.PPID); exists {
			newChildren := make([]apitypes.Process, 0, len(parent.Children))
			for _, child := range parent.Children {
				if child.PID != pid {
					newChildren = append(newChildren, child)
				}
			}
			parent.Children = newChildren
			p.processTree.Set(parent.PID, parent)
		}

		for _, child := range process.Children {
			if childProcess, exists := p.processTree.Load(child.PID); exists {
				childProcess.PPID = process.PPID
				p.addProcess(childProcess)
			}
		}

		p.processTree.Delete(pid)
	}
}

// GetProcessTreeForPID retrieves the process tree for a specific PID within a container.
// It returns the process and all its ancestors up to the container's shim process.
// If the process is not in the tree, it attempts to fetch it from /proc.
func (p *ProcessManager) GetProcessTreeForPID(containerID string, pid int) (apitypes.Process, error) {
	if !p.containerIdToShimPid.Has(containerID) {
		return apitypes.Process{}, fmt.Errorf("container ID %s not found", containerID)
	}

	targetPID := uint32(pid)
	if !p.processTree.Has(targetPID) {
		process, err := p.getProcessFromProc(pid)
		if err != nil {
			return apitypes.Process{}, fmt.Errorf("process %d not found: %v", pid, err)
		}
		p.addProcess(process)
	}

	result := p.processTree.Get(targetPID)
	currentPID := result.PPID
	seen := make(map[uint32]bool)

	for currentPID != p.containerIdToShimPid.Get(containerID) && currentPID != 0 {
		if seen[currentPID] {
			break
		}
		seen[currentPID] = true

		if p.processTree.Has(currentPID) {
			parent := p.processTree.Get(currentPID)
			parentCopy := parent
			parentCopy.Children = []apitypes.Process{result}
			result = parentCopy
			currentPID = parent.PPID
		} else {
			break
		}
	}

	return result, nil
}

// ReportEvent handles process execution events from the system.
// It specifically processes execve events to track new process creations
// and updates the process tree accordingly.
func (p *ProcessManager) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	if eventType != utils.ExecveEventType {
		return
	}

	execEvent, ok := event.(*tracerexectype.Event)
	if !ok {
		return
	}

	process := apitypes.Process{
		PID:        uint32(execEvent.Pid),
		PPID:       uint32(execEvent.Ppid),
		Comm:       execEvent.Comm,
		Uid:        &execEvent.Uid,
		Gid:        &execEvent.Gid,
		Hardlink:   execEvent.ExePath,
		UpperLayer: &execEvent.UpperLayer,
		Path:       execEvent.ExePath,
		Cwd:        execEvent.Cwd,
		Pcomm:      execEvent.Pcomm,
		Cmdline:    strings.Join(execEvent.Args, " "),
		Children:   []apitypes.Process{},
	}

	p.addProcess(process)
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
	deadPids := make(map[uint32]bool)
	p.processTree.Range(func(pid uint32, _ apitypes.Process) bool {
		if !isProcessAlive(int(pid)) {
			deadPids[pid] = true
		}
		return true
	})

	for pid := range deadPids {
		logger.L().Debug("Removing dead process", helpers.Int("pid", int(pid)))
		p.removeProcess(pid)
	}
}

// getProcessFromProc retrieves process information from the /proc filesystem
// for a given PID. It collects various process attributes such as command line,
// working directory, and user/group IDs.
func getProcessFromProc(pid int) (apitypes.Process, error) {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return apitypes.Process{}, fmt.Errorf("failed to get process info: %v", err)
	}

	stat, err := utils.GetProcessStat(pid)
	if err != nil {
		return apitypes.Process{}, fmt.Errorf("failed to get process stat: %v", err)
	}

	var uid, gid uint32
	if status, err := proc.NewStatus(); err == nil {
		if len(status.UIDs) > 1 {
			uid = uint32(status.UIDs[1])
		}
		if len(status.GIDs) > 1 {
			gid = uint32(status.GIDs[1])
		}
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

	return apitypes.Process{
		PID:      uint32(pid),
		PPID:     uint32(stat.PPID),
		Comm:     stat.Comm,
		Pcomm:    pcomm,
		Uid:      &uid,
		Gid:      &gid,
		Cmdline:  strings.Join(cmdline, " "),
		Cwd:      cwd,
		Path:     path,
		Children: []apitypes.Process{},
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
