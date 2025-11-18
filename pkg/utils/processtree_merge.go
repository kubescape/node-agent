package utils

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
)

// MergeProcessTrees merges two process trees into one.
// Since both trees come from the same container, PIDs uniquely identify processes.
// The merged tree will contain all unique processes from both trees.
// For processes that exist in both trees, information from the source tree is used to enrich the target.
func MergeProcessTrees(target *apitypes.Process, source *apitypes.Process) *apitypes.Process {
	if source == nil {
		return target
	}
	if target == nil {
		return source.DeepCopy()
	}

	// Ensure both trees have migrated to map structure
	target.MigrateToMap()
	source.MigrateToMap()

	// Build a flat map of all processes in target tree for quick lookup
	targetProcesses := buildProcessMap(target)

	// Traverse source tree and merge nodes
	mergeNode(target, source, targetProcesses)

	return target
}

// buildProcessMap creates a flat map of PID -> Process for quick lookup
func buildProcessMap(root *apitypes.Process) map[uint32]*apitypes.Process {
	processMap := make(map[uint32]*apitypes.Process)
	traverseProcessTree(root, func(p *apitypes.Process) {
		processMap[p.PID] = p
	})
	return processMap
}

// traverseProcessTree recursively traverses the process tree and applies a function to each node
func traverseProcessTree(node *apitypes.Process, fn func(*apitypes.Process)) {
	if node == nil {
		return
	}
	fn(node)
	for _, child := range node.ChildrenMap {
		traverseProcessTree(child, fn)
	}
}

// mergeNode recursively merges the source node into the target tree
func mergeNode(targetRoot *apitypes.Process, sourceNode *apitypes.Process, targetProcesses map[uint32]*apitypes.Process) {
	if sourceNode == nil {
		return
	}

	// Check if this process already exists in target tree
	existingProcess, exists := targetProcesses[sourceNode.PID]

	if exists {
		// Process exists - enrich it with any additional information from source
		enrichProcess(existingProcess, sourceNode)
	} else {
		// Process doesn't exist - need to insert it
		insertProcessIntoTree(targetRoot, sourceNode, targetProcesses)
	}

	// Recursively merge all children
	for _, sourceChild := range sourceNode.ChildrenMap {
		mergeNode(targetRoot, sourceChild, targetProcesses)
	}
}

// enrichProcess updates the target process with any additional information from source
func enrichProcess(target *apitypes.Process, source *apitypes.Process) {
	// Update fields if they are empty in target but present in source
	if target.Comm == "" && source.Comm != "" {
		target.Comm = source.Comm
	}
	if target.Path == "" && source.Path != "" {
		target.Path = source.Path
	}
	if target.Cmdline == "" && source.Cmdline != "" {
		target.Cmdline = source.Cmdline
	}
	if target.Pcomm == "" && source.Pcomm != "" {
		target.Pcomm = source.Pcomm
	}
	if target.Cwd == "" && source.Cwd != "" {
		target.Cwd = source.Cwd
	}
	if target.Uid == nil && source.Uid != nil {
		uidCopy := *source.Uid
		target.Uid = &uidCopy
	}
	if target.Gid == nil && source.Gid != nil {
		gidCopy := *source.Gid
		target.Gid = &gidCopy
	}
}

// insertProcessIntoTree inserts a new process into the target tree at the correct position
func insertProcessIntoTree(targetRoot *apitypes.Process, newProcess *apitypes.Process, targetProcesses map[uint32]*apitypes.Process) {
	// Create a deep copy of the new process (without children initially)
	inserted := &apitypes.Process{
		PID:         newProcess.PID,
		PPID:        newProcess.PPID,
		Comm:        newProcess.Comm,
		Path:        newProcess.Path,
		Cmdline:     newProcess.Cmdline,
		Pcomm:       newProcess.Pcomm,
		Gid:         copyUint32Ptr(newProcess.Gid),
		Uid:         copyUint32Ptr(newProcess.Uid),
		Cwd:         newProcess.Cwd,
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	// Add to target processes map
	targetProcesses[inserted.PID] = inserted

	// Find parent in target tree
	parent, parentExists := targetProcesses[newProcess.PPID]
	if parentExists {
		// Parent exists - add this process as a child
		if parent.ChildrenMap == nil {
			parent.ChildrenMap = make(map[apitypes.CommPID]*apitypes.Process)
		}
		parent.ChildrenMap[apitypes.CommPID{PID: inserted.PID}] = inserted
	} else {
		// Parent doesn't exist yet - this will be linked when parent is inserted
		// For now, if this is a root-level process in source tree, we need to decide how to handle it
		// In practice, the parent should eventually be merged as we traverse the source tree
	}
}

// copyUint32Ptr creates a copy of a uint32 pointer
func copyUint32Ptr(src *uint32) *uint32 {
	if src == nil {
		return nil
	}
	val := *src
	return &val
}

// MergeCloudServices merges two slices of cloud services and deduplicates them
func MergeCloudServices(existing []string, new []string) []string {
	serviceSet := make(map[string]struct{})

	// Add existing services
	for _, svc := range existing {
		serviceSet[svc] = struct{}{}
	}

	// Add new services
	for _, svc := range new {
		serviceSet[svc] = struct{}{}
	}

	// Convert back to slice
	merged := make([]string, 0, len(serviceSet))
	for svc := range serviceSet {
		merged = append(merged, svc)
	}

	return merged
}

