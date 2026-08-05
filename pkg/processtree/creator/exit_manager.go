package processtreecreator

import (
	"fmt"
	"sort"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
)

type pendingExit struct {
	PID uint32
	// StartTimeNs is NOT a process start time. It is the exit event's wall-clock
	// timestamp, and it exists only to order performExitCleanup's sort. Do not
	// repurpose it for identity, and never compare it against the boot-relative
	// pidStartTimeNs side map.
	StartTimeNs uint64
	Comm        string
	Timestamp   time.Time
	// ArrivalBootNs is when this exit was recorded, on CLOCK_BOOTTIME — the same
	// clock domain as pidStartTimeNs, so the two are comparable. Zero means the
	// clock read failed or was never wired, and makes the reuse guard fall
	// through to today's unconditional deletion.
	ArrivalBootNs uint64
	Children      []*armotypes.Process
}

func (pt *processTreeCreatorImpl) startExitManager() {
	pt.exitCleanupMutex.Lock()
	defer pt.exitCleanupMutex.Unlock()

	if pt.exitCleanupStopChan != nil {
		return
	}

	// Hand the channel to the loop by value. The loop must never read the field
	// itself: the field is mutable state shared with stopExitManager, and reading
	// it on every select iteration is what made this a data race.
	stopChan := make(chan struct{})
	pt.exitCleanupStopChan = stopChan
	go pt.exitCleanupLoop(stopChan)
}

func (pt *processTreeCreatorImpl) stopExitManager() {
	pt.exitCleanupMutex.Lock()
	defer pt.exitCleanupMutex.Unlock()

	if pt.exitCleanupStopChan == nil {
		return
	}

	// Closing is the signal that stops the loop; nil is only the "not running"
	// flag that lets startExitManager bring it back up. Holding the mutex across
	// the check and the close makes the transition atomic — previously two
	// concurrent Stop() calls could both find the channel open and both close it,
	// panicking with "close of closed channel".
	close(pt.exitCleanupStopChan)
	pt.exitCleanupStopChan = nil
}

// addPendingExit records a deferred exit. arrivalBootNs is passed in rather than
// read here, because the only caller holds pt.mutex and reading the boot clock is
// a syscall — see handleExitEvent. Zero means unknown and disables the reuse
// guard for this entry, falling through to today's unconditional deletion.
//
// Caller must hold pt.mutex.
func (pt *processTreeCreatorImpl) addPendingExit(event conversion.ProcessEvent, arrivalBootNs uint64) {
	if len(pt.pendingExits) >= pt.config.ExitCleanup.MaxPendingExits {
		logger.L().Debug("Exit: Maximum pending exits reached, forcing cleanup",
			helpers.String("pending_count", fmt.Sprintf("%d", len(pt.pendingExits))),
			helpers.String("max_allowed", fmt.Sprintf("%d", pt.config.ExitCleanup.MaxPendingExits)))
		pt.forceCleanupOldest()
	}

	pt.pendingExits[event.PID] = &pendingExit{
		PID:           event.PID,
		StartTimeNs:   event.StartTimeNs,
		Comm:          event.Comm,
		Timestamp:     time.Now(),
		ArrivalBootNs: arrivalBootNs,
	}
}

// bootTimeNs reads the boot clock through the injectable hook, returning 0 when
// the hook is absent or the read failed. Zero means "unknown" everywhere it is
// consumed, so an unset hook degrades every guard to today's behaviour rather
// than panicking — struct literals in tests need not wire it.
func (pt *processTreeCreatorImpl) bootTimeNs() uint64 {
	if pt.nowBootNs == nil {
		return 0
	}

	return pt.nowBootNs()
}

// exitCleanupLoop runs until it observes stopChan closed — which is not the same
// instant the close happens: an in-flight iteration is not preempted, and when
// both arms are ready the runtime picks between them at random, so one or two
// further cleanup passes after Stop() are normal.
//
// stopChan is a parameter rather than a field read so the loop holds its own
// reference for its whole lifetime, unaffected by a concurrent stopExitManager
// clearing the field.
func (pt *processTreeCreatorImpl) exitCleanupLoop(stopChan <-chan struct{}) {
	ticker := time.NewTicker(pt.config.ExitCleanup.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			pt.performExitCleanup()
		}
	}
}

func (pt *processTreeCreatorImpl) performExitCleanup() {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()
	now := time.Now()
	var toRemove []*pendingExit

	for _, pending := range pt.pendingExits {
		if now.Sub(pending.Timestamp) >= pt.config.ExitCleanup.CleanupDelay {
			toRemove = append(toRemove, pending)
		}
	}

	if len(toRemove) == 0 {
		return
	}

	sort.Slice(toRemove, func(i, j int) bool {
		return toRemove[i].StartTimeNs < toRemove[j].StartTimeNs
	})

	for _, pending := range toRemove {
		pt.exitByPid(pending.PID)
	}
}

func (pt *processTreeCreatorImpl) forceCleanupOldest() {
	if len(pt.pendingExits) == 0 {
		return
	}

	toRemove := make([]*pendingExit, 0, len(pt.pendingExits))
	for _, pending := range pt.pendingExits {
		toRemove = append(toRemove, pending)
	}

	sort.Slice(toRemove, func(i, j int) bool {
		return toRemove[i].Timestamp.Before(toRemove[j].Timestamp)
	})

	// One pass. There was a second, redundant pass over the same slice: harmless
	// while a repeat call always found the node already gone and returned silently,
	// but the reuse guard can now legitimately KEEP a node and consume its pending
	// entry on the first pass, so the second pass would find a node with no pending
	// entry and log a warning for it.
	for _, pending := range toRemove {
		pt.exitByPid(pending.PID)
	}

	logger.L().Debug("Exit: Force cleanup completed",
		helpers.String("remaining_pending", fmt.Sprintf("%d", len(pt.pendingExits))),
		helpers.Int("pids number", pt.processMap.Len()))
}

// retireRecycledPredecessor tears down the tree node of a dead process whose pid
// has been recycled, when a fork or exec proves a new incarnation now holds it.
//
// A fork or exec can only come from a live process — a zombie can do neither — so
// a pending exit on that pid must belong to a dead predecessor. Retiring it here
// does two things: it stops the new process inheriting the dead one's identity
// (handleForkEvent fills only empty fields, and a stale node is not empty), and
// it disarms the delayed deletion that would otherwise remove the new process's
// node up to cleanupDelay after the predecessor's exit.
//
// Retiring means the full exitByPid teardown, NOT merely dropping the pending
// entry. The dead process's children have to be reparented; leaving them linked
// to the pid would hand them to the new process as its own children, which is a
// quieter and worse corruption than the one being fixed.
//
// handleProcfsEvent must never call this. /proc lists zombies, so a procfs event
// can legitimately belong to the same incarnation that already exited, and the
// mere existence of a pending exit proves nothing there. Procfs recycle detection
// compares the recorded start time instead.
//
// Caller must hold pt.mutex.
func (pt *processTreeCreatorImpl) retireRecycledPredecessor(pid uint32) {
	if _, pending := pt.pendingExits[pid]; !pending {
		return
	}

	pt.exitByPid(pid)
}

func (pt *processTreeCreatorImpl) exitByPid(pid uint32) {
	// Pid-reuse guard (L2): if the node under this pid records a creation time
	// LATER than the moment this exit event arrived, it cannot be the process the
	// exit was for — the pid was recycled, and the predecessor's node is already
	// gone. Consume the pending entry so it is not retried forever, and keep the
	// node.
	//
	// Both sides are boot-relative nanoseconds: the side map is procfs ticks x
	// 10^7, the arrival is CLOCK_BOOTTIME. No btime skew, no wall-clock margin.
	// pendingExit.Timestamp and pendingExit.StartTimeNs are wall-clock values and
	// must never be used here.
	//
	// A zero on either side means unknown and falls through to today's deletion.
	// The guard must never KEEP a node it cannot prove is newer: retaining stale
	// state is the harmful direction, re-deleting a node is not. Nodes with no
	// recorded start time are therefore not covered by this layer at all — the
	// fork/exec guard covers those, needing no clock.
	// The node-absent case is settled first, so the guard below cannot return
	// while leaving an orphaned side-map entry behind. Side-map entries only exist
	// alongside nodes today, so ordering these the other way round is unreachable
	// rather than wrong — but it would depend on that invariant silently.
	if _, exists := pt.processMap.Load(pid); !exists {
		delete(pt.pendingExits, pid)
		delete(pt.pidStartTimeNs, pid)
		return
	}

	if pending := pt.pendingExits[pid]; pending != nil && pending.ArrivalBootNs != 0 {
		if startNs := pt.pidStartTimeNs[pid]; startNs > pending.ArrivalBootNs {
			delete(pt.pendingExits, pid)
			return
		}
	}

	pending := pt.pendingExits[pid]
	if pending == nil {
		logger.L().Warning("exitByPid: pendingExits[pid] is nil", helpers.String("pid", fmt.Sprintf("%d", pid)))
		return
	}

	children, removed := pt.removeProcessNode(pid)
	pending.Children = children

	if !removed {
		// Reparenting failed, so the node is still in the tree. Leave the pending
		// entry in place for the next cleanup tick — today's behaviour.
		return
	}

	delete(pt.pendingExits, pid)
}

// removeProcessNode tears one node out of the tree: it reparents the node's
// children, unlinks it from its parent, and deletes the node together with its
// process-identity entry. It returns the children it reparented, and false when
// the node could not be removed — today that means reparenting failed, and the
// caller must leave its own bookkeeping untouched so the operation degrades to
// today's retry-on-the-next-tick behaviour.
//
// Deliberately independent of pendingExits: the procfs recycle rebuild needs this
// exact teardown for a pid that has no pending exit at all, and duplicating the
// reparenting logic for it is how the two paths would drift.
//
// Caller must hold pt.mutex.
func (pt *processTreeCreatorImpl) removeProcessNode(pid uint32) ([]*armotypes.Process, bool) {
	proc, ok := pt.processMap.Load(pid)
	if !ok {
		delete(pt.pidStartTimeNs, pid)
		return nil, true
	}

	// Collect children for reparenting
	children := make([]*armotypes.Process, 0, len(proc.ChildrenMap))
	for _, child := range proc.ChildrenMap {
		if child != nil {
			children = append(children, child)
		}
	}

	if len(children) > 0 {
		// NewProcessTreeCreator leaves this nil if the strategy set cannot be
		// built, so treat a missing one as a removal failure rather than
		// dereferencing it. Unreachable today — NewReparentingLogic ends in an
		// unconditional `return rl, nil` — but the alternative is a nil-interface
		// panic, and with no recover() anywhere in the agent that takes the whole
		// process down rather than just this goroutine. This teardown also now has
		// a second caller on the procfs rebuild path.
		if pt.reparentingStrategies == nil {
			logger.L().Warning("removeProcessNode: no reparenting strategy, keeping node",
				helpers.String("pid", fmt.Sprintf("%d", pid)))
			return children, false
		}

		newParentPID, err := pt.reparentingStrategies.Reparent(pid, children, pt.containerTree, &pt.processMap)
		if err != nil {
			logger.L().Warning("removeProcessNode: reparenting failed", helpers.String("pid", fmt.Sprintf("%d", pid)), helpers.Error(err))
			return children, false
		}

		var newParentComm string
		if newParent, ok := pt.processMap.Load(newParentPID); ok {
			newParentComm = newParent.Comm
		}

		for _, child := range children {
			if child != nil {
				child.PPID = newParentPID
				if newParentComm != "" {
					child.Pcomm = newParentComm
				}
				pt.linkProcessToParent(child)
			}
		}
	}

	if proc.PPID != 0 {
		if parent, ok := pt.processMap.Load(proc.PPID); ok {
			if _, ok := parent.ChildrenMap[armotypes.CommPID{PID: pid}]; ok {
				delete(parent.ChildrenMap, armotypes.CommPID{PID: pid})
			} else {
				logger.L().Warning("removeProcessNode: process not found in parent's children map", helpers.String("pid", fmt.Sprintf("%d", pid)))
			}
		}
	}

	pt.processMap.Delete(pid)
	// The process identity dies with the node it identifies.
	delete(pt.pidStartTimeNs, pid)

	return children, true
}
