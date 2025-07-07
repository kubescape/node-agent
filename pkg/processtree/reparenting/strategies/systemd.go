package strategies

import (
	"fmt"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

// SystemdStrategy handles reparenting for systemd-managed processes
type SystemdStrategy struct{}

func (ss *SystemdStrategy) Name() string {
	return "systemd"
}

// IsApplicable checks if this strategy is applicable for the given scenario
// It checks if the exiting process is under a systemd hierarchy by walking up the process tree
func (ss *SystemdStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	// Check if the exiting process or any of its ancestors is systemd-related
	return ss.isProcessUnderSystemdHierarchy(exitingPID, processMap)
}

// isProcessUnderSystemdHierarchy checks if a process is under a systemd hierarchy by walking up the process tree
func (ss *SystemdStrategy) isProcessUnderSystemdHierarchy(pid uint32, processMap map[uint32]*apitypes.Process) bool {
	currentPID := pid
	visited := make(map[uint32]bool)
	maxDepth := 100 // Prevent infinite loops

	for depth := 0; depth < maxDepth; depth++ {
		if currentPID == 0 || visited[currentPID] {
			break
		}
		visited[currentPID] = true

		proc := processMap[currentPID]
		if proc == nil {
			break
		}

		// Check if current process is systemd-related
		if ss.isSystemdProcess(proc) {
			return true
		}

		// Move up to parent
		currentPID = proc.PPID
	}

	return false
}

// isSystemdProcess checks if a process is systemd-related
func (ss *SystemdStrategy) isSystemdProcess(proc *apitypes.Process) bool {
	if proc == nil {
		return false
	}

	comm := strings.ToLower(proc.Comm)
	systemdKeywords := []string{"systemd", "systemd-user-sessions", "systemd-logind", "systemd-udevd"}

	for _, keyword := range systemdKeywords {
		if strings.Contains(comm, keyword) {
			return true
		}
	}

	return false
}

// GetNewParentPID determines the new parent PID for orphaned children
// For systemd, orphaned processes are typically reparented to systemd (PID 1)
func (ss *SystemdStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	// Check if systemd is actually PID 1
	if systemdProc := processMap[1]; systemdProc != nil {
		if ss.isSystemdProcess(systemdProc) {
			logger.L().Info("SystemdStrategy: Reparenting to systemd",
				helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)))
			return 1
		}
	}

	// Fallback to init process
	logger.L().Info("SystemdStrategy: Systemd not found at PID 1, falling back to init",
		helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)))
	return 1
}
