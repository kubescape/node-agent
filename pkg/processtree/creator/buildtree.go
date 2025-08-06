package processtreecreator

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
)

// buildPathToRoot builds a path from the target process up to the root
func (pt *processTreeCreatorImpl) buildPathToRoot(targetProc *apitypes.Process) []*apitypes.Process {
	if targetProc == nil {
		return nil
	}

	var path []*apitypes.Process
	current := targetProc
	ok := true

	// Walk up the parent chain to the root
	for current != nil {
		path = append([]*apitypes.Process{current}, path...) // Prepend to get root-to-target order
		if current.PPID == 0 {
			break // Reached root
		}
		current, ok = pt.processMap.Load(current.PPID)
		if !ok {
			break
		}
	}

	return path
}

// buildBranchFromPath builds a process branch containing only the path from root to target
func (pt *processTreeCreatorImpl) buildBranchFromPath(path []*apitypes.Process) apitypes.Process {
	if len(path) == 0 {
		return apitypes.Process{}
	}

	// Start with the root (first in path)
	root := *path[0]
	root.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)

	// If there's only one process (root), return it
	if len(path) == 1 {
		return root
	}

	// Build the chain from root to target
	current := &root
	for i := 1; i < len(path); i++ {
		child := *path[i]
		child.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)

		key := apitypes.CommPID{Comm: child.Comm, PID: child.PID}
		current.ChildrenMap[key] = &child
		current = &child
	}

	return root
}
