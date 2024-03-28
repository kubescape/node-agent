package containerwatcher

import (
	"fmt"
	"os"
	"syscall"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// isUnixSocket checks if the given path is a Unix socket.
func isUnixSocket(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err // Could not obtain the file stats
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("not a unix file")
	}

	// Check if the file is a socket
	return (stat.Mode & syscall.S_IFMT) == syscall.S_IFSOCK, nil
}

func DetectContainerRuntime(hostMount string) (*containerutilsTypes.RuntimeConfig, error) {
	runtimes := map[igtypes.RuntimeName]string{
		igtypes.RuntimeNameDocker:     runtimeclient.DockerDefaultSocketPath,
		igtypes.RuntimeNameCrio:       runtimeclient.CrioDefaultSocketPath,
		igtypes.RuntimeNameContainerd: runtimeclient.ContainerdDefaultSocketPath,
		igtypes.RuntimeNamePodman:     runtimeclient.PodmanDefaultSocketPath,
	}
	for runtimeName, socketPath := range runtimes {
		// Check if the socket is available on the host mount
		socketPath = hostMount + socketPath
		if isSocket, err := isUnixSocket(socketPath); err == nil && isSocket {
			return &containerutilsTypes.RuntimeConfig{
				Name:       runtimeName,
				SocketPath: socketPath,
			}, nil
		}
	}

	// If no container runtime is detected, check if the container runtime is provided as an environment variable.
	containerRuntimeName := os.Getenv("CONTAINER_RUNTIME_NAME")
	containerRuntimeSocket := os.Getenv("CONTAINER_RUNTIME_SOCKET")
	if containerRuntimeName != "" && containerRuntimeSocket != "" {
		// Add the container runtime to the container collection
		return &containerutilsTypes.RuntimeConfig{
			Name:       igtypes.RuntimeName(containerRuntimeName),
			SocketPath: containerRuntimeSocket,
		}, nil
	}

	return nil, fmt.Errorf("no container runtime detected at the following paths: %v", runtimes)
}
