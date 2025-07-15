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

const (
	maxPendingExits = 20000           // Maximum number of pending exits before forcing cleanup
	cleanupInterval = 1 * time.Minute // Check every 5 minutes
	cleanupDelay    = 5 * time.Minute // Remove after 5 minutes
)

type pendingExit struct {
	PID         uint32
	StartTimeNs uint64
	Timestamp   time.Time
	Children    []*apitypes.Process
}

// Exit manager methods for processTreeCreatorImpl

// startExitManager starts the exit cleanup background process
func (pt *processTreeCreatorImpl) startExitManager() {
	if pt.exitCleanupStopChan != nil {
		return // Already started
	}

	pt.exitCleanupStopChan = make(chan struct{})
	go pt.exitCleanupLoop()
}

// stopExitManager stops the exit cleanup background process
func (pt *processTreeCreatorImpl) stopExitManager() {
	if pt.exitCleanupStopChan == nil {
		return // Not started
	}

	select {
	case <-pt.exitCleanupStopChan:
		// Already closed
		return
	default:
		close(pt.exitCleanupStopChan)
		pt.exitCleanupStopChan = nil
	}
}

// addPendingExit adds a process to the pending exit list
func (pt *processTreeCreatorImpl) addPendingExit(event feeder.ProcessEvent, children []*apitypes.Process) {
	// Check if we've reached the maximum pending exits
	if len(pt.pendingExits) >= maxPendingExits {
		logger.L().Warning("Exit: Maximum pending exits reached, forcing cleanup",
			helpers.String("pending_count", fmt.Sprintf("%d", len(pt.pendingExits))),
			helpers.String("max_allowed", fmt.Sprintf("%d", maxPendingExits)))

		// Force cleanup of oldest entries to make room
		pt.forceCleanupOldest()
	}

	pt.pendingExits[event.PID] = &pendingExit{
		PID:         event.PID,
		StartTimeNs: event.StartTimeNs,
		Timestamp:   time.Now(),
		Children:    children,
	}
}

// exitCleanupLoop runs the periodic cleanup every 5 minutes
func (pt *processTreeCreatorImpl) exitCleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pt.exitCleanupStopChan:
			return
		case <-ticker.C:
			pt.performExitCleanup()
		}
	}
}

// performExitCleanup removes processes that have been pending for more than the cleanup delay
func (pt *processTreeCreatorImpl) performExitCleanup() {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	now := time.Now()
	var toRemove []*pendingExit

	// Collect items to remove
	for _, pending := range pt.pendingExits {
		if now.Sub(pending.Timestamp) >= cleanupDelay {
			toRemove = append(toRemove, pending)
		}
	}

	if len(toRemove) == 0 {
		return
	}

	// Sort by StartTimeNs (oldest first)
	sort.Slice(toRemove, func(i, j int) bool {
		return toRemove[i].StartTimeNs < toRemove[j].StartTimeNs
	})

	// Remove the processes
	for _, pending := range toRemove {
		pt.removeProcessFromPending(pending.PID)
	}

	logger.L().Info("Exit: Cleaned up processes",
		helpers.String("count", fmt.Sprintf("%d", len(toRemove))))
}

// forceCleanupOldest removes the oldest 25% of pending processes to make room
// Caller must hold pt.mutex
func (pt *processTreeCreatorImpl) forceCleanupOldest() {
	if len(pt.pendingExits) == 0 {
		return
	}

	// Collect all pending exits
	toRemove := make([]*pendingExit, 0, len(pt.pendingExits))
	for _, pending := range pt.pendingExits {
		toRemove = append(toRemove, pending)
	}

	// Sort by timestamp (oldest first)
	sort.Slice(toRemove, func(i, j int) bool {
		return toRemove[i].Timestamp.Before(toRemove[j].Timestamp)
	})

	// Remove oldest 25% to make room
	removeCount := len(toRemove) / 4
	if removeCount < 1000 {
		removeCount = 1000 // Remove at least 1000 to ensure we have room
	}
	if removeCount > len(toRemove) {
		removeCount = len(toRemove)
	}

	logger.L().Debug("Exit: Force cleanup starting",
		helpers.String("total_pending", fmt.Sprintf("%d", len(pt.pendingExits))),
		helpers.String("removing_count", fmt.Sprintf("%d", removeCount)))

	for i := 0; i < removeCount; i++ {
		pt.removeProcessFromPending(toRemove[i].PID)
	}

	logger.L().Debug("Exit: Force cleanup completed",
		helpers.String("remaining_pending", fmt.Sprintf("%d", len(pt.pendingExits))))
}

// removeProcessFromPending removes a process from the pending list and handles actual removal
// Caller must hold pt.mutex
func (pt *processTreeCreatorImpl) removeProcessFromPending(pid uint32) {
	pending := pt.pendingExits[pid]
	if pending == nil {
		logger.L().Warning("removeProcessFromPending: pendingExits[pid] is nil", helpers.String("pid", fmt.Sprintf("%d", pid)))
		return
	}

	proc := pt.processMap.Get(pid)
	if proc == nil {
		logger.L().Warning("removeProcessFromPending: processMap[pid] does not exist", helpers.String("pid", fmt.Sprintf("%d", pid)))
		delete(pt.pendingExits, pid)
		return
	}

	// Handle reparenting of orphaned children
	if len(pending.Children) > 0 {
		if pt.reparentingLogic != nil {
			// Use the reparenting logic to determine the new parent
			result := pt.reparentingLogic.HandleProcessExit(pid, pending.Children, pt.containerTree, pt.getProcessMapAsRegularMap())

			// Update children's PPID to the new parent and link them
			for _, child := range pending.Children {
				if child != nil {
					child.PPID = result.NewParentPID
					pt.linkProcessToParent(child)
				}
			}
		} else {
			// Fallback to init process (PID 1) if reparenting logic is not available
			logger.L().Warning("Exit: Reparenting logic not available, using fallback to init",
				helpers.String("pid", fmt.Sprintf("%d", pid)))

			for _, child := range pending.Children {
				if child != nil {
					child.PPID = 1 // Adopted by init process
					pt.linkProcessToParent(child)
				}
			}
		}
	}

	// Remove from parent's children list
	if proc.PPID != 0 {
		if parent := pt.processMap.Get(proc.PPID); parent != nil {
			delete(parent.ChildrenMap, apitypes.CommPID{Comm: proc.Comm, PID: pid})
		}
	}

	// Remove the process from the map and pending list
	pt.processMap.Delete(pid)
	delete(pt.pendingExits, pid)

}
