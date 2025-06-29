package containerprocesstree

import (
	"sync"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type containerProcessTreeImpl struct {
	containerIdToShimPid map[string]uint32
	mutex                sync.RWMutex
}

func NewContainerProcessTree() ContainerProcessTree {
	return &containerProcessTreeImpl{
		containerIdToShimPid: make(map[string]uint32),
	}
}

func (c *containerProcessTreeImpl) ContainerCallback(notif containercollection.PubSubEvent) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	containerID := notif.Container.Runtime.BasicRuntimeMetadata.ContainerID

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		containerPID := notif.Container.ContainerPid()
		c.containerIdToShimPid[containerID] = containerPID
	case containercollection.EventTypeRemoveContainer:
		delete(c.containerIdToShimPid, containerID)
	}
}

func (c *containerProcessTreeImpl) GetContainerTree(containerID string, fullTree map[uint32]*apitypes.Process) ([]apitypes.Process, error) {
	c.mutex.RLock()
	shimPID, ok := c.containerIdToShimPid[containerID]
	c.mutex.RUnlock()
	logger.L().Debug("GetContainerTree", helpers.String("containerID", containerID), helpers.Interface("shimPID", shimPID))
	if !ok {
		logger.L().Debug("GetContainerTree Not found Shim PID", helpers.String("containerID", containerID), helpers.Interface("shimPID", shimPID))
		return nil, nil
	}

	// Find the process node for the shim PID
	shimNode := fullTree[shimPID]
	if shimNode == nil {
		logger.L().Debug("GetContainerTree Not found Shim PID", helpers.String("containerID", containerID), helpers.Interface("shimPID", shimPID))
		return nil, nil
	}

	// Recursively collect all descendants of the shim node
	var result []apitypes.Process
	var collect func(p *apitypes.Process)
	collect = func(p *apitypes.Process) {
		result = append(result, *p)
		for _, child := range p.ChildrenMap {
			collect(child)
		}
	}
	collect(shimNode)
	return result, nil
}

func (c *containerProcessTreeImpl) ListContainers() []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	ids := make([]string, 0, len(c.containerIdToShimPid))
	for id := range c.containerIdToShimPid {
		ids = append(ids, id)
	}
	return ids
}
