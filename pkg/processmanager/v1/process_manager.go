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
	maxTreeDepth    = 50 // Prevent infinite recursion
)

// ProcessManager manages container processes and their relationships
type ProcessManager struct {
	containerIdToShimPid maps.SafeMap[string, uint32]           // containerID -> shim pid
	processTree          maps.SafeMap[uint32, apitypes.Process] // pid -> process
}

// CreateProcessManager creates a new ProcessManager instance
func CreateProcessManager(ctx context.Context) *ProcessManager {
	pm := &ProcessManager{}

	// // Do initial process scan during initialization
	// if err := pm.initialProcScan(); err != nil {
	// 	logger.L().Warning("Failed initial process scan", helpers.Error(err))
	// }

	// Start cleanup routine
	go pm.startCleanupRoutine(ctx)

	return pm
}

// InitialProcScan performs a one-time scan of /proc to build the initial process tree
// Only processes that are descendants of existing container shims will be added
func (p *ProcessManager) InitialProcScan() error {
	// If we have no shims registered, nothing to do
	if len(p.containerIdToShimPid.Keys()) == 0 {
		return nil
	}

	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return fmt.Errorf("failed to open procfs: %v", err)
	}

	procs, err := fs.AllProcs()
	if err != nil {
		return fmt.Errorf("failed to read all procs: %v", err)
	}

	// First pass: collect all processes
	tempProcesses := make(map[uint32]apitypes.Process)
	for _, proc := range procs {
		if process, err := p.getProcessFromProc(proc.PID); err == nil {
			tempProcesses[process.PID] = process
		}
	}

	// Second pass: identify shim descendants and build relationships
	shimDescendants := make(map[uint32]bool)
	for pid, process := range tempProcesses {
		// Check if this process is a descendant of any registered shim
		if p.isDescendantOfShim(pid, make(map[uint32]bool)) {
			shimDescendants[pid] = true

			// Also mark all ancestors up to the shim as descendants
			currentPID := process.PPID
			visited := make(map[uint32]bool)
			for currentPID != 0 && !visited[currentPID] {
				visited[currentPID] = true
				if proc, exists := tempProcesses[currentPID]; exists {
					shimDescendants[currentPID] = true
					currentPID = proc.PPID
				} else {
					break
				}
			}
		}
	}

	// Final pass: add only shim-related processes and build relationships
	for pid, process := range tempProcesses {
		if !shimDescendants[pid] {
			continue // Skip processes not related to shims
		}

		// If parent exists and is also a shim descendant, update parent's children
		if parent, exists := tempProcesses[process.PPID]; exists && shimDescendants[process.PPID] {
			parent.Children = append(parent.Children, process)
			tempProcesses[process.PPID] = parent
		}

		// Add process to the tree
		p.processTree.Set(pid, process)
	}

	logger.L().Debug("Initial process scan completed",
		helpers.Int("total_processes", len(tempProcesses)),
		helpers.Int("shim_related_processes", len(shimDescendants)))

	return nil
}

// addProcess adds a process to the tree and updates relationships
func (p *ProcessManager) addProcess(process apitypes.Process) {
	// Add the process to the tree
	p.processTree.Set(process.PID, process)

	// Update parent's children list if parent exists
	if parent, exists := p.processTree.Load(process.PPID); exists {
		// Create new children slice to avoid modifying existing one
		newChildren := make([]apitypes.Process, 0, len(parent.Children)+1)
		// Add existing children, excluding any old version of this process
		for _, child := range parent.Children {
			if child.PID != process.PID {
				newChildren = append(newChildren, child)
			}
		}
		// Add the new process
		newChildren = append(newChildren, process)
		parent.Children = newChildren
		p.processTree.Set(parent.PID, parent)
	}
}

// removeProcess removes a process and updates relationships
func (p *ProcessManager) removeProcess(pid uint32) {
	// Get the process before removing it
	if process, exists := p.processTree.Load(pid); exists {
		// Update parent's children list
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

		// Reassign children to nearest living ancestor
		for _, child := range process.Children {
			if newProcess, exists := p.processTree.Load(child.PID); exists {
				newProcess.PPID = process.PPID
				p.addProcess(newProcess) // This will update the new parent's children list
			}
		}

		// Finally remove the process
		p.processTree.Delete(pid)
	}
}

// isDescendantOfShim checks if a process is a descendant of any container shim
func (p *ProcessManager) isDescendantOfShim(pid uint32, visited map[uint32]bool) bool {
	if pid == 0 || len(visited) > maxTreeDepth {
		return false
	}

	if visited[pid] {
		return false // Avoid cycles
	}
	visited[pid] = true

	// Check if this pid is a shim
	isShim := false
	p.containerIdToShimPid.Range(func(_ string, shimPid uint32) bool {
		if shimPid == pid {
			isShim = true
			return false // Stop ranging
		}
		return true
	})

	if isShim {
		return true
	}

	// Check parent if process exists
	if process, exists := p.processTree.Load(pid); exists {
		return p.isDescendantOfShim(process.PPID, visited)
	}

	return false
}

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

func (p *ProcessManager) cleanup() {
	// First pass: identify dead processes
	deadPids := make(map[uint32]bool)
	p.processTree.Range(func(pid uint32, _ apitypes.Process) bool {
		if !isProcessAlive(int(pid)) {
			deadPids[pid] = true
		}
		return true
	})

	// Second pass: remove dead processes and update relationships
	for pid := range deadPids {
		p.removeProcess(pid)
	}
}

func (p *ProcessManager) ContainerCallback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		containerID := notif.Container.Runtime.ContainerID
		shimPID := uint32(notif.Container.Pid)

		// Store the shim PID
		p.containerIdToShimPid.Set(containerID, shimPID)

		// If the shim process isn't in our tree yet (might have started after initial scan),
		// add it directly
		if !p.processTree.Has(shimPID) {
			if process, err := p.getProcessFromProc(int(shimPID)); err == nil {
				p.addProcess(process)
			} else {
				logger.L().Debug("Failed to get shim process info",
					helpers.String("containerID", containerID),
					helpers.Error(err))
			}
		}

	case containercollection.EventTypeRemoveContainer:
		containerID := notif.Container.Runtime.ContainerID

		// Get shim PID before removing the mapping
		if shimPID, exists := p.containerIdToShimPid.Load(containerID); exists {
			// Remove all descendants of this shim
			descendants := make(map[uint32]bool)
			p.processTree.Range(func(pid uint32, process apitypes.Process) bool {
				if p.isDescendantOfShim(pid, make(map[uint32]bool)) {
					descendants[pid] = true
				}
				return true
			})

			// Remove descendants in reverse order (children before parents)
			for pid := range descendants {
				p.removeProcess(pid)
			}

			// Finally remove the shim itself
			p.removeProcess(shimPID)
		}

		// Remove the container mapping
		p.containerIdToShimPid.Delete(containerID)
	}
}

func (p *ProcessManager) GetProcessTreeForPID(containerID string, pid int) (apitypes.Process, error) {
	if !p.containerIdToShimPid.Has(containerID) {
		return apitypes.Process{}, fmt.Errorf("container ID %s not found", containerID)
	}

	shimPID := p.containerIdToShimPid.Get(containerID)
	targetPID := uint32(pid)

	// If process doesn't exist in our tree, try to fetch it
	if !p.processTree.Has(targetPID) {
		// Only fetch if it's a descendant of our shim
		if process, err := p.getProcessFromProc(int(targetPID)); err == nil {
			p.addProcess(process)
		} else {
			return apitypes.Process{}, fmt.Errorf("process %d not found: %v", pid, err)
		}
	}

	// Build process tree from target up to shim
	processes := make([]apitypes.Process, 0)
	currentPID := targetPID
	seen := make(map[uint32]bool)

	// Collect all processes up to shim
	for currentPID != 0 && currentPID != shimPID {
		if seen[currentPID] {
			break // Avoid cycles
		}
		seen[currentPID] = true

		if proc, exists := p.processTree.Load(currentPID); exists {
			processes = append([]apitypes.Process{proc}, processes...) // Prepend
			currentPID = proc.PPID
		} else {
			break
		}
	}

	// No processes found or invalid tree
	if len(processes) == 0 {
		return apitypes.Process{}, fmt.Errorf("could not build process tree for pid %d", pid)
	}

	// Build the tree structure
	result := processes[0]
	current := &result

	// Link processes together
	for i := 1; i < len(processes); i++ {
		child := processes[i]
		current.Children = []apitypes.Process{child}
		current = &current.Children[0]
	}

	// Add the target process as the final leaf if it's not already in the chain
	if current.PID != targetPID {
		if targetProc, exists := p.processTree.Load(targetPID); exists {
			current.Children = []apitypes.Process{targetProc}
		}
	}

	return result, nil
}

func (p *ProcessManager) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	if eventType != utils.ExecveEventType {
		return
	}

	execEvent, ok := event.(*tracerexectype.Event)
	if !ok {
		return
	}

	// Create new process from event
	process := apitypes.Process{
		PID:     execEvent.Pid,
		PPID:    execEvent.Ppid,
		Comm:    execEvent.Comm,
		Uid:     &execEvent.Uid,
		Gid:     &execEvent.Gid,
		Cmdline: strings.Join(execEvent.Args, " "),
	}

	p.addProcess(process)
}

func (p *ProcessManager) getProcessFromProc(pid int) (apitypes.Process, error) {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return apitypes.Process{}, fmt.Errorf("failed to get process info: %v", err)
	}

	stat, err := utils.GetProcessStat(pid)
	if err != nil {
		return apitypes.Process{}, fmt.Errorf("failed to get process stat: %v", err)
	}

	// Get process details
	var uid, gid uint32
	if status, err := proc.NewStatus(); err == nil {
		if len(status.UIDs) > 1 {
			uid = uint32(status.UIDs[1])
		}
		if len(status.GIDs) > 1 {
			gid = uint32(status.GIDs[1])
		}
	}

	cmdline, err := proc.CmdLine()
	if err != nil {
		cmdline = []string{stat.Comm} // Fallback to comm if cmdline fails
	}

	cwd, err := proc.Cwd()
	if err != nil {
		cwd = "" // Empty string if we can't get cwd
	}

	path, err := proc.Executable()
	if err != nil {
		path = "" // Empty string if we can't get executable path
	}

	return apitypes.Process{
		PID:     uint32(pid),
		PPID:    uint32(stat.PPID),
		Comm:    stat.Comm,
		Uid:     &uid,
		Gid:     &gid,
		Cmdline: strings.Join(cmdline, " "),
		Cwd:     cwd,
		Path:    path,
	}, nil
}

func isProcessAlive(pid int) bool {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return false
	}
	_, err = proc.Stat()
	return err == nil
}
