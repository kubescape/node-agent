package processtree

import (
	"sync"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
)

type processTreeCreatorImpl struct {
	mutex      sync.RWMutex
	processMap map[uint32]*apitypes.Process // PID -> Process
}

func NewProcessTreeCreator() ProcessTreeCreator {
	return &processTreeCreatorImpl{
		processMap: make(map[uint32]*apitypes.Process),
	}
}

func (pt *processTreeCreatorImpl) FeedEvent(event feeder.ProcessEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	switch event.Type {
	case feeder.ForkEvent:
		pt.handleForkOrProcfsEvent(event, false)
	case feeder.ProcfsEvent:
		pt.handleForkOrProcfsEvent(event, true)
	case feeder.ExecEvent:
		// Update process info on exec
		proc := pt.getOrCreateProcess(event.PID)
		proc.PID = event.PID
		proc.PPID = event.PPID
		proc.Comm = event.Comm
		proc.Pcomm = event.Pcomm
		proc.Cmdline = event.Cmdline
		proc.Uid = event.Uid
		proc.Gid = event.Gid
		proc.Cwd = event.Cwd
		proc.Path = event.Path
		if proc.ChildrenMap == nil {
			proc.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
		}
	case feeder.ExitEvent:
		// Remove process from tree
		delete(pt.processMap, event.PID)
	}
}

func (pt *processTreeCreatorImpl) GetNodeTree() ([]apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	// Find root processes (those whose parent is not in the map or PPID==0)
	roots := []apitypes.Process{}
	for _, proc := range pt.processMap {
		if proc.PPID == 0 || pt.processMap[proc.PPID] == nil {
			roots = append(roots, *pt.deepCopyProcess(proc))
		}
	}
	return roots, nil
}

func (pt *processTreeCreatorImpl) GetProcessNode(pid int) (*apitypes.Process, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	proc, ok := pt.processMap[uint32(pid)]
	if !ok {
		return nil, nil
	}
	return pt.deepCopyProcess(proc), nil
}

// handleForkOrProcfsEvent handles both Fork and Procfs events, with enrichment for Procfs.
func (pt *processTreeCreatorImpl) handleForkOrProcfsEvent(event feeder.ProcessEvent, enrichExisting bool) {
	proc, exists := pt.processMap[event.PID]
	if !exists {
		proc = &apitypes.Process{PID: event.PID, ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
		pt.processMap[event.PID] = proc
	}
	if enrichExisting && exists {
		// Only update fields if the new value is non-empty and the existing value is empty or default
		if event.PPID != 0 && proc.PPID == 0 {
			proc.PPID = event.PPID
		}
		if event.Comm != "" && proc.Comm == "" {
			proc.Comm = event.Comm
		}
		if event.Pcomm != "" && proc.Pcomm == "" {
			proc.Pcomm = event.Pcomm
		}
		if event.Cmdline != "" && proc.Cmdline == "" {
			proc.Cmdline = event.Cmdline
		}
		if event.Uid != nil && proc.Uid == nil {
			proc.Uid = event.Uid
		}
		if event.Gid != nil && proc.Gid == nil {
			proc.Gid = event.Gid
		}
		if event.Cwd != "" && proc.Cwd == "" {
			proc.Cwd = event.Cwd
		}
		if event.Path != "" && proc.Path == "" {
			proc.Path = event.Path
		}
	} else {
		// Overwrite or set all fields
		proc.PID = event.PID
		proc.PPID = event.PPID
		proc.Comm = event.Comm
		proc.Pcomm = event.Pcomm
		proc.Cmdline = event.Cmdline
		proc.Uid = event.Uid
		proc.Gid = event.Gid
		proc.Cwd = event.Cwd
		proc.Path = event.Path
	}
	if proc.ChildrenMap == nil {
		proc.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
	}
	// Link to parent
	if event.PPID != 0 {
		parent := pt.getOrCreateProcess(event.PPID)
		if parent.ChildrenMap == nil {
			parent.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
		}
		parent.ChildrenMap[apitypes.CommPID{Comm: event.Comm, PID: event.PID}] = proc
	}
}

func (pt *processTreeCreatorImpl) getOrCreateProcess(pid uint32) *apitypes.Process {
	if proc, ok := pt.processMap[pid]; ok {
		return proc
	}
	proc := &apitypes.Process{PID: pid, ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	pt.processMap[pid] = proc
	return proc
}

func (pt *processTreeCreatorImpl) deepCopyProcess(proc *apitypes.Process) *apitypes.Process {
	if proc == nil {
		return nil
	}
	copy := *proc
	copy.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
	for k, v := range proc.ChildrenMap {
		copy.ChildrenMap[k] = pt.deepCopyProcess(v)
	}
	return &copy
}
