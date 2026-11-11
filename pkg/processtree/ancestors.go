package processtree

import (
	"github.com/armosec/armoapi-go/armotypes"
)

// GetAncestorPIDs returns pid's ancestors, nearest first, up to maxDepth entries.
// pid itself is excluded.
//
// This walks the creator's global process map rather than
// containerTree.GetPidBranch, because GetPidBranch resolves a container shim and
// errors out when there is none -- which is every host / cgroup-0 process. Walking
// the map works identically for containerised and host processes.
//
// maxDepth also bounds the walk defensively: a reparenting race could in
// principle produce a parent cycle, and the evaluator must not hang.
func (ptm *ProcessTreeManagerImpl) GetAncestorPIDs(pid uint32, maxDepth int) []uint32 {
	if maxDepth <= 0 {
		return nil
	}

	var out []uint32
	seen := make(map[uint32]struct{}, maxDepth)
	current := pid

	for len(out) < maxDepth {
		var node *armotypes.Process
		func() {
			ptm.mutex.RLock()
			defer ptm.mutex.RUnlock()
			node, _ = ptm.creator.GetProcessNode(int(current))
		}()
		// PPID 0 means "parent unknown", not "parent is pid 0" -- recording it
		// would add a key no state entry can ever be stored under.
		if node == nil || node.PPID == 0 {
			break
		}
		if _, dup := seen[node.PPID]; dup {
			break
		}
		seen[node.PPID] = struct{}{}
		out = append(out, node.PPID)
		if node.PPID == 1 {
			break
		}
		current = node.PPID
	}
	return out
}
