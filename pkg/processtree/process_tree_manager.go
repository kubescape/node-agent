package processtree

import (
	"fmt"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/hashicorp/golang-lru/v2/expirable"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	processtreecreator "github.com/kubescape/node-agent/pkg/processtree/creator"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/kubescape/node-agent/pkg/utils"
)

// ProcessTreeManagerImpl implements the ProcessTreeManager interface
type ProcessTreeManagerImpl struct {
	creator                   processtreecreator.ProcessTreeCreator
	containerTree             containerprocesstree.ContainerProcessTree
	eventFeeder               *feeder.EventFeeder
	containerProcessTreeCache *expirable.LRU[string, apitypes.Process] // containerID:pid -> cached result
}

// NewProcessTreeManager creates a new process tree manager
func NewProcessTreeManager(
	creator processtreecreator.ProcessTreeCreator,
	containerTree containerprocesstree.ContainerProcessTree,
	eventFeeder *feeder.EventFeeder,
) ProcessTreeManager {

	containerProcessTreeCache := expirable.NewLRU[string, apitypes.Process](10000, nil, 1*time.Minute)

	return &ProcessTreeManagerImpl{
		creator:                   creator,
		containerTree:             containerTree,
		eventFeeder:               eventFeeder,
		containerProcessTreeCache: containerProcessTreeCache,
	}
}

func (ptm *ProcessTreeManagerImpl) ReportEvent(eventType utils.EventType, event utils.K8sEvent) error {
	var processEvent feeder.ProcessEvent
	processEvent, err := ptm.eventFeeder.ConvertEvent(eventType, event)
	if err != nil {
		return fmt.Errorf("failed to convert event: %v", err)
	}

	ptm.creator.FeedEvent(processEvent)

	return nil
}

func (ptm *ProcessTreeManagerImpl) GetHostProcessTree() ([]apitypes.Process, error) {
	return ptm.creator.GetRootTree()
}

func (ptm *ProcessTreeManagerImpl) GetContainerProcessTree(containerID string, pid uint32) (apitypes.Process, error) {
	cacheKey := fmt.Sprintf("%s:%d", containerID, pid)
	if cached, exists := ptm.containerProcessTreeCache.Get(cacheKey); exists {
		return cached, nil
	}

	processNode, err := ptm.creator.GetProcessNode(int(pid))
	if err != nil {
		return apitypes.Process{}, fmt.Errorf("failed to get process node: %v", err)
	}

	if processNode == nil {
		return apitypes.Process{}, fmt.Errorf("process with PID %d not found in container %s", pid, containerID)
	}

	containerSubtree, subtreeErr := ptm.containerTree.GetContainerSubtree(containerID, pid, ptm.creator.GetProcessMap())
	if subtreeErr != nil {
		return apitypes.Process{}, fmt.Errorf("failed to get container subtree: %v", subtreeErr)
	}

	ptm.containerProcessTreeCache.Add(cacheKey, containerSubtree)

	return containerSubtree, nil
}

func (ptm *ProcessTreeManagerImpl) GetProcessNode(pid int) (*apitypes.Process, error) {
	return ptm.creator.GetProcessNode(pid)
}
