package containerprocesstree

import (
	"sync"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type containerProcessTreeImpl struct {
	containerIdToShimPid map[string]apitypes.CommPID
	mutex                sync.RWMutex
	lastFullTree         []apitypes.Process // cache the last full tree for shim PID inference
}

func NewContainerProcessTree() ContainerProcessTree {
	return &containerProcessTreeImpl{
		containerIdToShimPid: make(map[string]apitypes.CommPID),
	}
}

func (c *containerProcessTreeImpl) ContainerCallback(notif containercollection.PubSubEvent) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	containerID := notif.Container.Runtime.BasicRuntimeMetadata.ContainerID

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		containerPID := notif.Container.ContainerPid()
		// Try to infer shim PID as the parent of the container process from the last full tree
		var shimPID apitypes.CommPID
		for i := range c.lastFullTree {
			if c.lastFullTree[i].PID == containerPID {
				shimPID = apitypes.CommPID{Comm: c.lastFullTree[i].Pcomm, PID: c.lastFullTree[i].PPID}
				break
			}
		}
		if shimPID.PID != 0 {
			c.containerIdToShimPid[containerID] = shimPID
		}
	case containercollection.EventTypeRemoveContainer:
		delete(c.containerIdToShimPid, containerID)
	}
}

func (c *containerProcessTreeImpl) GetContainerTree(containerID string, fullTree []apitypes.Process) ([]apitypes.Process, error) {
	c.mutex.Lock()
	c.lastFullTree = fullTree
	shimPID, ok := c.containerIdToShimPid[containerID]
	c.mutex.Unlock()
	if !ok {
		return nil, nil
	}

	// Find the process node for the shim PID
	var shimNode *apitypes.Process
	for i := range fullTree {
		if fullTree[i].PID == shimPID.PID && fullTree[i].Comm == shimPID.Comm {
			shimNode = &fullTree[i]
			break
		}
	}
	if shimNode == nil {
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
