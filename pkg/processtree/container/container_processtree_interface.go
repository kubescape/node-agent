package containerprocesstree

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type ContainerProcessTree interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	GetContainerTree(containerID string, fullTree map[uint32]*apitypes.Process) ([]apitypes.Process, error)
	ListContainers() []string
}
