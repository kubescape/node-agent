package utils

import (
	"fmt"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

// PrintTreeOneLine prints the process tree in a single line showing the hierarchy
// Format: "root(pid,ppid) -> child1(pid,ppid) -> child2(pid,ppid) | sibling1(pid,ppid) -> grandchild(pid,ppid)"
func PrintTreeOneLine(process *apitypes.Process) string {
	if process == nil {
		return "nil"
	}

	var result strings.Builder
	printTreeOneLineRecursive(process, &result, 0)
	return result.String()
}

// printTreeOneLineRecursive recursively builds the tree string
func printTreeOneLineRecursive(process *apitypes.Process, result *strings.Builder, depth int) {
	if process == nil {
		return
	}

	// Add the current process
	if depth > 0 {
		result.WriteString(" -> ")
	}

	// Format: comm(pid,ppid) or pid(pid,ppid) if comm is empty
	if process.Comm != "" {
		result.WriteString(fmt.Sprintf("%s(%d,%d)", process.Comm, process.PID, process.PPID))
	} else {
		result.WriteString(fmt.Sprintf("pid(%d,%d)", process.PID, process.PPID))
	}

	// Handle children
	if len(process.ChildrenMap) > 0 {
		children := make([]*apitypes.Process, 0, len(process.ChildrenMap))
		for _, child := range process.ChildrenMap {
			if child != nil {
				children = append(children, child)
			}
		}

		if len(children) == 1 {
			// Single child - continue the chain
			printTreeOneLineRecursive(children[0], result, depth+1)
		} else if len(children) > 1 {
			// Multiple children - use | separator
			for i, child := range children {
				if i > 0 {
					result.WriteString(" | ")
					// Add the parent prefix for siblings
					if process.Comm != "" {
						result.WriteString(fmt.Sprintf("%s(%d,%d) -> ", process.Comm, process.PID, process.PPID))
					} else {
						result.WriteString(fmt.Sprintf("pid(%d,%d) -> ", process.PID, process.PPID))
					}
					// For siblings, we don't want the recursive call to add another arrow
					printTreeOneLineRecursive(child, result, 0)
				} else {
					// First child continues the chain normally
					printTreeOneLineRecursive(child, result, depth+1)
				}
			}
		}
	}
}

// PrintTreeOneLineCompact prints a more compact version of the tree
// Format: "root(ppid)->child1(ppid)->child2(ppid)|sibling1(ppid)->grandchild(ppid)"
func PrintTreeOneLineCompact(process *apitypes.Process) string {
	if process == nil {
		return "nil"
	}

	var result strings.Builder
	printTreeOneLineCompactRecursive(process, &result, 0)
	return result.String()
}

// printTreeOneLineCompactRecursive recursively builds the compact tree string
func printTreeOneLineCompactRecursive(process *apitypes.Process, result *strings.Builder, depth int) {
	if process == nil {
		return
	}

	// Add the current process
	if depth > 0 {
		result.WriteString("->")
	}

	// Use comm if available, otherwise just pid, and include ppid in parentheses
	if process.Comm != "" {
		result.WriteString(fmt.Sprintf("%s(%d)", process.Comm, process.PPID))
	} else {
		result.WriteString(fmt.Sprintf("%d(%d)", process.PID, process.PPID))
	}

	// Handle children
	if len(process.ChildrenMap) > 0 {
		children := make([]*apitypes.Process, 0, len(process.ChildrenMap))
		for _, child := range process.ChildrenMap {
			if child != nil {
				children = append(children, child)
			}
		}

		if len(children) == 1 {
			// Single child - continue the chain
			printTreeOneLineCompactRecursive(children[0], result, depth+1)
		} else if len(children) > 1 {
			// Multiple children - use | separator
			for i, child := range children {
				if i > 0 {
					result.WriteString("|")
					// Add the parent prefix for siblings
					if process.Comm != "" {
						result.WriteString(fmt.Sprintf("%s(%d)", process.Comm, process.PPID))
					} else {
						result.WriteString(fmt.Sprintf("%d(%d)", process.PID, process.PPID))
					}
					result.WriteString("->")
					// For siblings, we don't want the recursive call to add another arrow
					printTreeOneLineCompactRecursive(child, result, 0)
				} else {
					// First child continues the chain normally
					printTreeOneLineCompactRecursive(child, result, depth+1)
				}
			}
		}
	}
}

// PrintTreeOneLineWithPIDs prints the tree with PIDs and PPIDs for maximum compactness
// Format: "1(0)->2(1)->3(2)|2(1)->4(2)"
func PrintTreeOneLineWithPIDs(process *apitypes.Process) string {
	if process == nil {
		return "nil"
	}

	var result strings.Builder
	printTreeOneLineWithPIDsRecursive(process, &result, 0)
	return result.String()
}

// printTreeOneLineWithPIDsRecursive recursively builds the PID-only tree string
func printTreeOneLineWithPIDsRecursive(process *apitypes.Process, result *strings.Builder, depth int) {
	if process == nil {
		return
	}

	// Add the current process PID and PPID
	if depth > 0 {
		result.WriteString("->")
	}
	result.WriteString(fmt.Sprintf("%d(%d)", process.PID, process.PPID))

	// Handle children
	if len(process.ChildrenMap) > 0 {
		children := make([]*apitypes.Process, 0, len(process.ChildrenMap))
		for _, child := range process.ChildrenMap {
			if child != nil {
				children = append(children, child)
			}
		}

		if len(children) == 1 {
			// Single child - continue the chain
			printTreeOneLineWithPIDsRecursive(children[0], result, depth+1)
		} else if len(children) > 1 {
			// Multiple children - use | separator
			for i, child := range children {
				if i > 0 {
					result.WriteString("|")
					// Add the parent PID and PPID for siblings
					result.WriteString(fmt.Sprintf("%d(%d)->", process.PID, process.PPID))
					// For siblings, we don't want the recursive call to add another arrow
					printTreeOneLineWithPIDsRecursive(child, result, 0)
				} else {
					// First child continues the chain normally
					printTreeOneLineWithPIDsRecursive(child, result, depth+1)
				}
			}
		}
	}
}
