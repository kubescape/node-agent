package processtree

import (
	"context"
	"fmt"
	"sync"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	processtreecreator "github.com/kubescape/node-agent/pkg/processtree/creator"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
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
	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()

	if !ptm.started {
		return apitypes.Process{}, fmt.Errorf("process tree manager not started")
	}

	fullTree := ptm.creator.GetProcessMap()
	// Get all processes in the container
	containerProcesses, err := ptm.containerTree.GetContainerTree(containerID, fullTree)
	if err != nil {
		return apitypes.Process{}, fmt.Errorf("failed to get container tree: %v", err)
	}

	// If no container processes found, return empty process
	if len(containerProcesses) == 0 {
		pids := []uint32{}
		for i := range fullTree {
			pids = append(pids, fullTree[i].PID)
		}
		return apitypes.Process{}, fmt.Errorf("no processes found for container %s, pids: %v", containerID, pids)
	}

	// Find the specific process with the given PID
	processesPids := []uint32{}
	for _, process := range containerProcesses {
		processesPids = append(processesPids, process.PID)
		if process.PID == pid {
			return process, nil
		}
		// Also search in children recursively
		if found := ptm.findProcessByPID(&process, pid); found != nil {
			return *found, nil
		}

	}

	processNode, err := ptm.creator.GetProcessNode(int(pid))
	if err != nil {
		return apitypes.Process{}, fmt.Errorf("failed to get process node: %v", err)
	}

	logger.L().Debug("Not tContainerProcessTree processNode", helpers.Int("pid", int(pid)), helpers.String("containerID", containerID), helpers.Interface("processNode", processNode))
	if processNode != nil && processNode.ChildrenMap != nil {
		for _, process := range processNode.ChildrenMap {
			logger.L().Debug("Not GetContainerProcessTree processNode children", helpers.Int("pid", int(process.PID)), helpers.String("containerID", containerID), helpers.Interface("processNode", process))
		}
	} else {
		logger.L().Debug("Not GetContainerProcessTree processNode children", helpers.Int("pid", int(pid)), helpers.String("containerID", containerID), helpers.Interface("processNode", processNode))
	}

	return apitypes.Process{}, fmt.Errorf("process with PID %d not found in container %s, pids: %v", pid, containerID, processesPids)
}

// findProcessByPID recursively searches for a process with the given PID in the process tree
func (ptm *ProcessTreeManagerImpl) findProcessByPID(process *apitypes.Process, targetPID uint32) *apitypes.Process {
	if process.PID == targetPID {
		return process
	}

	for _, child := range process.ChildrenMap {
		if found := ptm.findProcessByPID(child, targetPID); found != nil {
			return found
		}
	}

	return nil
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
