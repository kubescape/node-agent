package utils

import (
	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

// IsHostContainer reports whether container is the virtual host
// pseudo-container, identified either by its synthetic container ID
// (armotypes.HostContainerID) or by running with PID 1 on the host PID
// namespace. Use this when a full *containercollection.Container is
// available; when only a containerID string is available, use IsHost instead.
func IsHostContainer(container *containercollection.Container) bool {
	if container == nil {
		return false
	}
	return container.Runtime.ContainerPID == 1 || container.Runtime.ContainerID == armotypes.HostContainerID
}

// HasKubernetesPodIdentity reports whether a container identifies an addressable
// Kubernetes Pod. Other runtime metadata cannot be used for a Pod lookup.
// Container-name enrichment is not required to acquire the Pod's shared data.
func HasKubernetesPodIdentity(container *containercollection.Container) bool {
	if container == nil {
		return false
	}
	return container.K8s.Namespace != "" && container.K8s.PodName != ""
}

// IsHost reports whether containerID identifies the virtual host
// pseudo-container (armotypes.HostContainerID). This is the single choke
// point for the "is this the host" check wherever only a containerID string
// is available (not a full *containercollection.Container, which
// IsHostContainer checks instead).
func IsHost(containerID string) bool {
	return containerID == armotypes.HostContainerID
}
