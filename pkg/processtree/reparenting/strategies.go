package reparenting

import (
	"fmt"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

// ContainerdStrategy handles reparenting for containerd-based containers
type ContainerdStrategy struct{}

func (cs *ContainerdStrategy) Name() string {
	return "containerd"
}

func (cs *ContainerdStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	// Check if the exiting process is under a containerd-shim subtree
	return containerTree != nil && containerTree.IsProcessUnderAnyContainerSubtree(exitingPID, processMap)
}

func (cs *ContainerdStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	// For containerd, orphaned processes are typically reparented to the shim process
	if containerTree != nil {
		shimPID, found := containerTree.GetShimPIDForProcess(exitingPID, processMap)
		if found {
			logger.L().Info("ContainerdStrategy: Reparenting to shim",
				helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)),
				helpers.String("shim_pid", fmt.Sprintf("%d", shimPID)))
			return shimPID
		}
	}

	// Fallback to init process if shim not found or containerTree is nil
	logger.L().Warning("ContainerdStrategy: Shim not found or containerTree is nil, falling back to init",
		helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)))
	return 1
}

// SystemdStrategy handles reparenting for systemd-managed processes
type SystemdStrategy struct{}

func (ss *SystemdStrategy) Name() string {
	return "systemd"
}

func (ss *SystemdStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	// Check if the exiting process or its parent is systemd-related
	exitingProc := processMap[exitingPID]
	if exitingProc == nil {
		return false
	}

	// Check if the process name contains systemd
	if strings.Contains(strings.ToLower(exitingProc.Comm), "systemd") {
		return true
	}

	// Check if parent is systemd
	if exitingProc.PPID != 0 {
		if parentProc := processMap[exitingProc.PPID]; parentProc != nil {
			if strings.Contains(strings.ToLower(parentProc.Comm), "systemd") {
				return true
			}
		}
	}

	return false
}

func (ss *SystemdStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	// For systemd, orphaned processes are typically reparented to systemd (PID 1)
	// But we need to check if systemd is actually PID 1
	if systemdProc := processMap[1]; systemdProc != nil {
		if strings.Contains(strings.ToLower(systemdProc.Comm), "systemd") {
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

// DockerStrategy handles reparenting for Docker containers
type DockerStrategy struct{}

func (ds *DockerStrategy) Name() string {
	return "docker"
}

func (ds *DockerStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	// Check if the exiting process is under a docker-related subtree
	exitingProc := processMap[exitingPID]
	if exitingProc == nil {
		return false
	}

	// Check if the process name contains docker
	if strings.Contains(strings.ToLower(exitingProc.Comm), "docker") {
		return true
	}

	// Check if parent is docker-related
	if exitingProc.PPID != 0 {
		if parentProc := processMap[exitingProc.PPID]; parentProc != nil {
			if strings.Contains(strings.ToLower(parentProc.Comm), "docker") {
				return true
			}
		}
	}

	return false
}

func (ds *DockerStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	// For Docker, orphaned processes are typically reparented to the docker daemon
	// Look for docker daemon process
	for pid, proc := range processMap {
		if strings.Contains(strings.ToLower(proc.Comm), "dockerd") {
			logger.L().Info("DockerStrategy: Reparenting to dockerd",
				helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)),
				helpers.String("dockerd_pid", fmt.Sprintf("%d", pid)))
			return pid
		}
	}

	// Fallback to init process
	logger.L().Info("DockerStrategy: Dockerd not found, falling back to init",
		helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)))
	return 1
}

// DefaultStrategy handles reparenting for general cases
type DefaultStrategy struct{}

func (defs *DefaultStrategy) Name() string {
	return "default"
}

func (defs *DefaultStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	// Default strategy is always applicable as a fallback
	return true
}

func (defs *DefaultStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	// Default behavior: reparent to init process (PID 1)
	logger.L().Info("DefaultStrategy: Reparenting to init",
		helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)))
	return 1
}
