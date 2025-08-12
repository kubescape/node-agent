package processtreecreator

import (
	"fmt"
	"sort"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
)

type pendingExit struct {
	PID         uint32
	StartTimeNs uint64
	Timestamp   time.Time
	Children    []*apitypes.Process
}

func (pt *processTreeCreatorImpl) startExitManager() {
	if pt.exitCleanupStopChan != nil {
		return
	}

	pt.exitCleanupStopChan = make(chan struct{})
	go pt.exitCleanupLoop()
}

func (pt *processTreeCreatorImpl) stopExitManager() {
	if pt.exitCleanupStopChan == nil {
		return
	}

	select {
	case <-pt.exitCleanupStopChan:
		return
	default:
		close(pt.exitCleanupStopChan)
		pt.exitCleanupStopChan = nil
	}
}

func (pt *processTreeCreatorImpl) addPendingExit(event conversion.ProcessEvent, children []*apitypes.Process) {
	if len(pt.pendingExits) >= pt.config.ExitCleanup.MaxPendingExits {
		logger.L().Debug("Exit: Maximum pending exits reached, forcing cleanup",
			helpers.String("pending_count", fmt.Sprintf("%d", len(pt.pendingExits))),
			helpers.String("max_allowed", fmt.Sprintf("%d", pt.config.ExitCleanup.MaxPendingExits)))
		pt.forceCleanupOldest()
	}

	pt.pendingExits[event.PID] = &pendingExit{
		PID:         event.PID,
		StartTimeNs: event.StartTimeNs,
		Timestamp:   time.Now(),
		Children:    children,
	}
}

func (pt *processTreeCreatorImpl) exitCleanupLoop() {
	ticker := time.NewTicker(pt.config.ExitCleanup.CleanupInterval)
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

	removeCount := len(toRemove) / 4
	if removeCount < 1000 {
		removeCount = 1000
	}
	if removeCount > len(toRemove) {
		removeCount = len(toRemove)
	}

	for i := 0; i < removeCount; i++ {
		pt.exitByPid(toRemove[i].PID)
	}

	logger.L().Debug("Exit: Force cleanup completed",
		helpers.String("remaining_pending", fmt.Sprintf("%d", len(pt.pendingExits))))
}

func (pt *processTreeCreatorImpl) exitByPid(pid uint32) {
	pending := pt.pendingExits[pid]
	if pending == nil {
		logger.L().Warning("exitByPid: pendingExits[pid] is nil", helpers.String("pid", fmt.Sprintf("%d", pid)))
		return
	}

	proc, ok := pt.processMap.Load(pid)
	if !ok {
		logger.L().Warning("exitByPid: processMap[pid] does not exist", helpers.String("pid", fmt.Sprintf("%d", pid)))
		delete(pt.pendingExits, pid)
		return
	}

	if len(pending.Children) > 0 {
		newParentPID, err := pt.reparentingStrategies.Reparent(pid, pending.Children, pt.containerTree, &pt.processMap)
		if err != nil {
			logger.L().Warning("exitByPid: reparentingLogic.HandleProcessExit failed", helpers.String("pid", fmt.Sprintf("%d", pid)), helpers.Error(err))
			return
		}

		for _, child := range pending.Children {
			if child != nil {
				child.PPID = newParentPID
				pt.linkProcessToParent(child)
			}
		}
	}

	if proc.PPID != 0 {
		if parent, ok := pt.processMap.Load(proc.PPID); ok {
			delete(parent.ChildrenMap, apitypes.CommPID{Comm: proc.Comm, PID: pid})
		}
	}

	pt.processMap.Delete(pid)
	delete(pt.pendingExits, pid)
}
