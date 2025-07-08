package strategies

import (
	"fmt"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

// DockerStrategy handles reparenting for Docker containers
type DockerStrategy struct{}

func (ds *DockerStrategy) Name() string {
	return "docker"
}

// IsApplicable checks if this strategy is applicable for the given scenario
// It checks if the exiting process is under a docker-related hierarchy by walking up the process tree
func (ds *DockerStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	// Check if the exiting process or any of its ancestors is docker-related
	return ds.isProcessUnderDockerHierarchy(exitingPID, processMap)
}

// isProcessUnderDockerHierarchy checks if a process is under a docker hierarchy by walking up the process tree
func (ds *DockerStrategy) isProcessUnderDockerHierarchy(pid uint32, processMap map[uint32]*apitypes.Process) bool {
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

		// Check if current process is docker-related
		if ds.isDockerProcess(proc) {
			return true
		}

		// Move up to parent
		currentPID = proc.PPID
	}

	return false
}

// isDockerProcess checks if a process is docker-related
func (ds *DockerStrategy) isDockerProcess(proc *apitypes.Process) bool {
	if proc == nil {
		return false
	}

	comm := strings.ToLower(proc.Comm)
	dockerKeywords := []string{"docker", "dockerd", "docker-proxy", "docker-containerd", "docker-init"}

	for _, keyword := range dockerKeywords {
		if strings.Contains(comm, keyword) {
			return true
		}
	}

	return false
}

// GetNewParentPID determines the new parent PID for orphaned children
// For Docker, orphaned processes are typically reparented to the docker daemon
func (ds *DockerStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	// Instead of iterating over the entire process map, walk up the process tree
	// from the exiting process to find a docker-related parent
	currentPID := exitingPID
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

		// Check if current process is dockerd
		if ds.isDockerProcess(proc) && strings.Contains(strings.ToLower(proc.Comm), "dockerd") {
			logger.L().Info("DockerStrategy: Reparenting to dockerd",
				helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)),
				helpers.String("dockerd_pid", fmt.Sprintf("%d", currentPID)))
			return currentPID
		}

		// Move up to parent
		currentPID = proc.PPID
	}

	// Fallback to init process
	logger.L().Info("DockerStrategy: Dockerd not found, falling back to init",
		helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)))
	return 1
}
