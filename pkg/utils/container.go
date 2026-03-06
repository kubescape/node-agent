package utils

import containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"

const HostContainerID = "host"

func IsHostContainer(container *containercollection.Container) bool {
	if container == nil {
		return false
	}
	return container.Runtime.ContainerPID == 1 || container.Runtime.ContainerID == HostContainerID
}
