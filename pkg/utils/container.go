package utils

import (
	"github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

func IsHostContainer(container *containercollection.Container) bool {
	if container == nil {
		return false
	}
	return container.Runtime.ContainerPID == 1 || container.Runtime.ContainerID == armotypes.HostContainerID
}
