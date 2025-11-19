package utils

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
)

// FlattenChainToList converts a chain-structured process tree into an ordered list (root-first)
// A chain is a single path from container init to the offending process
// This is optimized for the common case where each alert provides one linear path
func FlattenChainToList(root *apitypes.Process) []*apitypes.Process {
	if root == nil {
		return nil
	}

	result := make([]*apitypes.Process, 0, 10) // Typical chain length: container init -> parent -> ... -> offender
	current := root

	for current != nil {
		result = append(result, current)

		// In a chain, there's only one child (or none at the leaf)
		// Navigate to the single child
		if len(current.ChildrenMap) == 0 {
			break
		}

		// Get the single child in the chain
		var child *apitypes.Process
		for _, c := range current.ChildrenMap {
			child = c
			break // Only one child in a chain
		}
		current = child
	}

	return result
}

// CopyProcess creates a deep copy of a process node (without children)
// Children map is initialized empty so the caller can rebuild the tree structure
func CopyProcess(src *apitypes.Process) *apitypes.Process {
	if src == nil {
		return nil
	}

	return &apitypes.Process{
		PID:         src.PID,
		PPID:        src.PPID,
		Comm:        src.Comm,
		Path:        src.Path,
		Cmdline:     src.Cmdline,
		Pcomm:       src.Pcomm,
		Cwd:         src.Cwd,
		Gid:         copyUint32Ptr(src.Gid),
		Uid:         copyUint32Ptr(src.Uid),
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
}

// EnrichProcess updates target with non-empty fields from source
// This is used when merging process information from multiple alerts
// Only overwrites fields that are empty in target but present in source
func EnrichProcess(target *apitypes.Process, source *apitypes.Process) {
	if target == nil || source == nil {
		return
	}

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
		target.Uid = copyUint32Ptr(source.Uid)
	}
	if target.Gid == nil && source.Gid != nil {
		target.Gid = copyUint32Ptr(source.Gid)
	}
}

// copyUint32Ptr creates a copy of a uint32 pointer
// This prevents pointer aliasing when copying process structures
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
