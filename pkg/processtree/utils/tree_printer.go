package utils

import (
	"fmt"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

// PrintTreeOneLine prints the process tree in a single line showing the hierarchy
// Format: "root(pid) -> child1(pid) -> child2(pid) | sibling1(pid) -> grandchild(pid)"
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

	// Format: comm(pid) or just pid if comm is empty
	if process.Comm != "" {
		result.WriteString(fmt.Sprintf("%s(%d)", process.Comm, process.PID))
	} else {
		result.WriteString(fmt.Sprintf("pid(%d)", process.PID))
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
						result.WriteString(fmt.Sprintf("%s(%d) -> ", process.Comm, process.PID))
					} else {
						result.WriteString(fmt.Sprintf("pid(%d) -> ", process.PID))
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
// Format: "root->child1->child2|sibling1->grandchild"
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

	// Use comm if available, otherwise just pid
	if process.Comm != "" {
		result.WriteString(process.Comm)
	} else {
		result.WriteString(fmt.Sprintf("%d", process.PID))
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
						result.WriteString(process.Comm)
					} else {
						result.WriteString(fmt.Sprintf("%d", process.PID))
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

// PrintTreeOneLineWithPIDs prints the tree with only PIDs for maximum compactness
// Format: "1->2->3|2->4"
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

	// Add the current process PID
	if depth > 0 {
		result.WriteString("->")
	}
	result.WriteString(fmt.Sprintf("%d", process.PID))

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
					// Add the parent PID for siblings
					result.WriteString(fmt.Sprintf("%d->", process.PID))
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
