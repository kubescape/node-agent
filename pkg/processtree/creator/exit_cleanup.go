package processtreecreator

import (
	"fmt"
	"sort"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
)

// ExitCleanupManager handles delayed removal of exited processes
// NOTE: All public methods must be called with the creator's mutex held.
type ExitCleanupManager struct {
	pendingExits    map[uint32]*pendingExit
	cleanupInterval time.Duration
	cleanupDelay    time.Duration
	stopChan        chan struct{}
	creator         *processTreeCreatorImpl
}

type pendingExit struct {
	PID         uint32
	StartTimeNs uint64
	Timestamp   time.Time
	Children    []*apitypes.Process
}

// NewExitCleanupManager creates a new exit cleanup manager
func NewExitCleanupManager(creator *processTreeCreatorImpl) *ExitCleanupManager {
	return &ExitCleanupManager{
		pendingExits:    make(map[uint32]*pendingExit),
		cleanupInterval: 5 * time.Second,  // Check every 5 seconds
		cleanupDelay:    15 * time.Second, // Remove after 15 seconds
		stopChan:        make(chan struct{}),
		creator:         creator,
	}
}

// Start begins the cleanup goroutine
func (ecm *ExitCleanupManager) Start() {
	go ecm.cleanupLoop()
}

// Stop stops the cleanup goroutine
func (ecm *ExitCleanupManager) Stop() {
	close(ecm.stopChan)
}

// AddPendingExit adds a process to the pending exit list
// Caller must hold creator.mutex
func (ecm *ExitCleanupManager) AddPendingExit(event feeder.ProcessEvent, children []*apitypes.Process) {
	// Only add to pendingExits if the process still exists
	if _, exists := ecm.creator.processMap[event.PID]; !exists {
		logger.L().Info("Exit: Not adding to pending cleanup, process already removed",
			helpers.String("pid", fmt.Sprintf("%d", event.PID)))
		return
	}

	ecm.pendingExits[event.PID] = &pendingExit{
		PID:         event.PID,
		StartTimeNs: event.StartTimeNs,
		Timestamp:   time.Now(),
		Children:    children,
	}
	logger.L().Info("Exit: Added to pending cleanup",
		helpers.String("pid", fmt.Sprintf("%d", event.PID)),
		helpers.String("children_count", fmt.Sprintf("%d", len(children))))
}

// cleanupLoop runs the periodic cleanup
func (ecm *ExitCleanupManager) cleanupLoop() {
	ticker := time.NewTicker(ecm.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ecm.stopChan:
			return
		case <-ticker.C:
			ecm.performCleanup()
		}
	}
}

// performCleanup removes processes that have been pending for more than the cleanup delay
// Caller must hold creator.mutex
func (ecm *ExitCleanupManager) performCleanup() {
	now := time.Now()
	toRemove := make([]*pendingExit, 0)

	// Find processes that should be removed
	for _, pending := range ecm.pendingExits {
		if now.Sub(pending.Timestamp) >= ecm.cleanupDelay {
			toRemove = append(toRemove, pending)
		}
	}

	// Sort by StartTimeNs (oldest first)
	sort.Slice(toRemove, func(i, j int) bool {
		return toRemove[i].StartTimeNs < toRemove[j].StartTimeNs
	})

	// Remove the processes in order
	for _, pending := range toRemove {
		ecm.removeProcess(pending.PID)
	}

	if len(toRemove) > 0 {
		logger.L().Info("Exit: Cleaned up processes",
			helpers.String("count", fmt.Sprintf("%d", len(toRemove))))
	}
}

// forceCleanup removes all pending processes immediately (for testing purposes)
// Caller must hold creator.mutex
func (ecm *ExitCleanupManager) forceCleanup() {
	toRemove := make([]*pendingExit, 0)
	for _, pending := range ecm.pendingExits {
		toRemove = append(toRemove, pending)
	}

	// Sort by StartTimeNs (oldest first)
	sort.Slice(toRemove, func(i, j int) bool {
		return toRemove[i].StartTimeNs < toRemove[j].StartTimeNs
	})

	// Remove the processes in order
	for _, pending := range toRemove {
		ecm.removeProcess(pending.PID)
	}

	if len(toRemove) > 0 {
		logger.L().Info("Exit: Force cleaned up processes",
			helpers.String("count", fmt.Sprintf("%d", len(toRemove))))
	}
}

// removeProcess removes a process from the tree and handles reparenting
// Caller must hold creator.mutex
func (ecm *ExitCleanupManager) removeProcess(pid uint32) {
	pending := ecm.pendingExits[pid]
	if pending == nil {
		return
	}

	// Get the process from the creator's map
	proc, exists := ecm.creator.processMap[pid]
	if !exists {
		// Process was already removed, just clean up our pending list
		delete(ecm.pendingExits, pid)
		logger.L().Info("Exit: Process already removed from map",
			helpers.String("pid", fmt.Sprintf("%d", pid)))
		return
	}

	// Handle reparenting of orphaned children
	if len(pending.Children) > 0 {
		if ecm.creator.reparentingLogic != nil {
			// Use the reparenting logic to determine the new parent
			result := ecm.creator.reparentingLogic.HandleProcessExit(pid, pending.Children, ecm.creator.containerTree, ecm.creator.processMap)

			logger.L().Info("Exit: Delayed reparenting result",
				helpers.String("pid", fmt.Sprintf("%d", pid)),
				helpers.String("strategy", result.Strategy),
				helpers.String("new_parent_pid", fmt.Sprintf("%d", result.NewParentPID)),
				helpers.String("verified", fmt.Sprintf("%t", result.Verified)),
				helpers.String("children_count", fmt.Sprintf("%d", len(pending.Children))))

			// Update children's PPID to the new parent and link them
			for _, child := range pending.Children {
				if child != nil {
					child.PPID = result.NewParentPID
					ecm.creator.linkProcessToParent(child)
				}
			}
		} else {
			// Fallback to init process (PID 1) if reparenting logic is not available
			logger.L().Warning("Exit: Reparenting logic not available, using fallback to init",
				helpers.String("pid", fmt.Sprintf("%d", pid)))

			for _, child := range pending.Children {
				if child != nil {
					child.PPID = 1 // Adopted by init process
					ecm.creator.linkProcessToParent(child)
				}
			}
		}
	}

	// Remove from parent's children list
	if proc.PPID != 0 {
		if parent, parentExists := ecm.creator.processMap[proc.PPID]; parentExists {
			delete(parent.ChildrenMap, apitypes.CommPID{Comm: proc.Comm, PID: pid})
		}
	}

	// Remove the process from the map
	delete(ecm.creator.processMap, pid)
	delete(ecm.pendingExits, pid)

	logger.L().Info("Exit: Removed process after delay",
		helpers.String("pid", fmt.Sprintf("%d", pid)),
		helpers.String("start_time_ns", fmt.Sprintf("%d", pending.StartTimeNs)))
}
