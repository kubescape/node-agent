package processtree

import (
	"context"
	"fmt"
	"sync"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
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

	// Processed events tracking
	processedExecEvents *lru.Cache[uint32, bool] // PID -> processed flag

	// Container process tree cache with automatic expiration
	containerProcessTreeCache *expirable.LRU[string, apitypes.Process] // containerID:pid -> cached result

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

	// Create LRU cache for processed exec events with size 1000
	processedExecEvents, err := lru.New[uint32, bool](10000)
	if err != nil {
		// Fallback to nil cache if creation fails
		processedExecEvents = nil
	}

	// Create expirable LRU cache for container process tree with size 10000 and 1 minute TTL
	containerProcessTreeCache := expirable.NewLRU[string, apitypes.Process](10000, nil, 1*time.Minute)

	return &ProcessTreeManagerImpl{
		creator:                   creator,
		containerTree:             containerTree,
		feeders:                   feeders,
		eventChan:                 make(chan feeder.ProcessEvent, 1000), // Buffer for events
		processedExecEvents:       processedExecEvents,
		containerProcessTreeCache: containerProcessTreeCache,
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

			// Track processed exec events
			if event.Type == feeder.ExecEvent && ptm.processedExecEvents != nil {
				ptm.processedExecEvents.Add(event.PID, true)
			}
		}
	}
}

func (ptm *ProcessTreeManagerImpl) cleanup() {
	close(ptm.eventChan)
}

// WaitForProcessProcessing waits for a process to be processed by the process tree manager
// This ensures that the process tree is updated before rule evaluation
func (ptm *ProcessTreeManagerImpl) WaitForProcessProcessing(pid uint32, timeout time.Duration) error {
	if ptm.processedExecEvents == nil {
		// If cache is not available, wait a short time and return
		time.Sleep(10 * time.Millisecond)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(1 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for process processing: pid=%d", pid)
		case <-ticker.C:
			if _, exists := ptm.processedExecEvents.Get(pid); exists {
				return nil
			}
		}
	}
}
