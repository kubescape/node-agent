package processtree

import (
	"context"
	"fmt"
	"sync"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	processtreecreator "github.com/kubescape/node-agent/pkg/processtree/creator"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/kubescape/node-agent/pkg/processtree/utils"
)

// ProcessTreeManagerImpl implements the ProcessTreeManager interface
type ProcessTreeManagerImpl struct {
	// Core components
	creator       processtreecreator.ProcessTreeCreator
	containerTree containerprocesstree.ContainerProcessTree
	feeders       []feeder.ProcessEventFeeder

	// Event handling
	eventChan chan feeder.ProcessEvent

	// Lifecycle management
	ctx     context.Context
	cancel  context.CancelFunc
	started bool
	stopped bool
	mutex   sync.RWMutex
}

// NewProcessTreeManager creates a new process tree manager
func NewProcessTreeManager(
	creator processtreecreator.ProcessTreeCreator,
	containerTree containerprocesstree.ContainerProcessTree,
	feeders []feeder.ProcessEventFeeder,
) ProcessTreeManager {
	// Set the container tree in the creator for container-aware PPID management
	creator.SetContainerTree(containerTree)

	return &ProcessTreeManagerImpl{
		creator:       creator,
		containerTree: containerTree,
		feeders:       feeders,
		eventChan:     make(chan feeder.ProcessEvent, 1000), // Buffer for events
	}
}

func (ptm *ProcessTreeManagerImpl) Start(ctx context.Context) error {
	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	if ptm.started {
		return fmt.Errorf("process tree manager already started")
	}

	if ptm.stopped {
		return fmt.Errorf("process tree manager has been stopped and cannot be restarted")
	}

	ptm.ctx, ptm.cancel = context.WithCancel(ctx)

	// Start all feeders
	for _, f := range ptm.feeders {
		if err := f.Start(ptm.ctx); err != nil {
			ptm.cleanup()
			return fmt.Errorf("failed to start feeder: %v", err)
		}
		// Subscribe the feeder to our event channel
		f.Subscribe(ptm.eventChan)
	}

	// Start event processing goroutine
	go ptm.eventProcessor()

	ptm.started = true
	return nil
}

// Stop gracefully stops the process tree manager
func (ptm *ProcessTreeManagerImpl) Stop() error {
	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	if !ptm.started || ptm.stopped {
		return nil
	}

	ptm.stopped = true

	// Cancel context to stop all goroutines
	if ptm.cancel != nil {
		ptm.cancel()
	}

	// Stop all feeders
	for _, f := range ptm.feeders {
		if err := f.Stop(); err != nil {
			// Log error but continue stopping other components
			// In a real implementation, you might want to use a logger here
			_ = err
		}
	}

	ptm.cleanup()
	return nil
}

func (ptm *ProcessTreeManagerImpl) GetHostProcessTree() ([]apitypes.Process, error) {
	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()

	if !ptm.started {
		return nil, fmt.Errorf("process tree manager not started")
	}

	return ptm.creator.GetRootTree()
}

func (ptm *ProcessTreeManagerImpl) GetContainerProcessTree(containerID string, pid uint32) (apitypes.Process, error) {
	// Try to get the process tree immediately
	processTree, err := ptm.getContainerProcessTreeInternal(containerID, pid)
	if err == nil {
		return processTree, nil
	}

	// If we failed, wait up to 500ms for events to be processed and try again
	processTree, err = ptm.retryGetContainerProcessTree(containerID, pid, err)
	if err != nil {
		logger.L().Error("Failed to get container process tree", helpers.Error(err), helpers.String("containerID", containerID), helpers.Int("pid", int(pid)))
		return apitypes.Process{}, fmt.Errorf("failed to get container process tree: %v", err)
	}
	
	return processTree, nil
}

func (ptm *ProcessTreeManagerImpl) getContainerProcessTreeInternal(containerID string, pid uint32) (apitypes.Process, error) {
	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()

	if !ptm.started {
		return apitypes.Process{}, fmt.Errorf("process tree manager not started")
	}

	processNode, err := ptm.creator.GetProcessNode(int(pid))
	if err != nil {
		return apitypes.Process{}, fmt.Errorf("failed to get process node: %v", err)
	}

	if processNode == nil {
		return apitypes.Process{}, fmt.Errorf("process with PID %d not found in container %s", pid, containerID)
	}

	// Get the container subtree starting from the node just before shim PID
	containerSubtree, err := ptm.containerTree.GetContainerSubtree(containerID, pid, ptm.creator.GetProcessMap())
	if err != nil {
		return apitypes.Process{}, fmt.Errorf("failed to get container subtree: %v", err)
	}

	return containerSubtree, nil
}

func (ptm *ProcessTreeManagerImpl) GetProcessNode(pid int) (*apitypes.Process, error) {
	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()

	if !ptm.started {
		return nil, fmt.Errorf("process tree manager not started")
	}

	return ptm.creator.GetProcessNode(pid)
}

func (ptm *ProcessTreeManagerImpl) eventProcessor() {
	for {
		select {
		case <-ptm.ctx.Done():
			return
		case event := <-ptm.eventChan:
			ptm.creator.FeedEvent(event)
		}
	}
}

func (ptm *ProcessTreeManagerImpl) cleanup() {
	close(ptm.eventChan)
}

func (ptm *ProcessTreeManagerImpl) retryGetContainerProcessTree(containerID string, pid uint32, originalErr error) (apitypes.Process, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ptm.handleTimeoutError(containerID, pid, originalErr)
		case <-ticker.C:
			processTree, err := ptm.getContainerProcessTreeInternal(containerID, pid)
			if err == nil {
				return processTree, nil
			}
		}
	}
}

func (ptm *ProcessTreeManagerImpl) handleTimeoutError(containerID string, pid uint32, originalErr error) (apitypes.Process, error) {
	processNode, _ := ptm.creator.GetProcessNode(int(pid))
	logger.L().Error("Failed to get process node after waiting", helpers.Error(originalErr), helpers.String("processNode", utils.PrintTreeOneLine(processNode)))

	if processNode == nil {
		logger.L().Error("Process not found after waiting", helpers.String("pid", fmt.Sprintf("%d", pid)), helpers.String("containerID", containerID))
		return apitypes.Process{}, fmt.Errorf("process with PID %d not found in container %s after waiting", pid, containerID)
	}

	// Try to get container subtree one more time for better error logging
	containerSubtree, subtreeErr := ptm.containerTree.GetContainerSubtree(containerID, pid, ptm.creator.GetProcessMap())
	if subtreeErr != nil {
		ptm.logContainerSubtreeError(containerID, pid, processNode, subtreeErr)
		return apitypes.Process{}, fmt.Errorf("failed to get container subtree after waiting: %v", subtreeErr)
	}

	return containerSubtree, nil
}

func (ptm *ProcessTreeManagerImpl) logContainerSubtreeError(containerID string, pid uint32, processNode *apitypes.Process, subtreeErr error) {
	logger.L().Error("Failed to get container subtree after waiting", helpers.Error(subtreeErr))

	nodes, nodesErr := ptm.containerTree.GetContainerTreeNodes(containerID, ptm.creator.GetProcessMap())
	if nodesErr != nil {
		logger.L().Error("Failed to get container tree nodes after waiting", helpers.Error(nodesErr), helpers.String("processNode", utils.PrintTreeOneLine(processNode)))
	}
	if len(nodes) > 0 {
		logger.L().Error("Container tree nodes after waiting", helpers.String("GetContainerTreeNodes", utils.PrintTreeOneLine(&nodes[0])))
	}
	logger.L().Error("Failed to get container subtree after waiting", helpers.String("processNode", utils.PrintTreeOneLine(processNode)))
}
