package filetree

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	fimtypes "github.com/kubescape/node-agent/pkg/hostfimsensor"
)

const (
	// MaxRecursionDepth limits the maximum depth of directory recursion to prevent stack overflow
	MaxRecursionDepth = 50
)

// buildPathFromComponents efficiently builds a full path from components
func buildPathFromComponents(components []string) string {
	if len(components) == 0 {
		return "/"
	}
	return "/" + strings.Join(components, "/")
}

// ChangeType represents the type of change detected
type ChangeType string

const (
	ChangeTypeCreate ChangeType = "create"
	ChangeTypeModify ChangeType = "modify"
	ChangeTypeDelete ChangeType = "delete"
	ChangeTypeMove   ChangeType = "move"
	ChangeTypeChmod  ChangeType = "chmod"
	ChangeTypeRename ChangeType = "rename"
)

// FileChange represents a detected change in the file system
type FileChange struct {
	Type      ChangeType
	Path      string
	OldNode   *FileNode // nil for create
	NewNode   *FileNode // nil for delete
	Timestamp time.Time
}

// TreeComparator compares two file tree snapshots and detects changes
type TreeComparator struct {
}

// NewTreeComparator creates a new tree comparator
func NewTreeComparator() *TreeComparator {
	return &TreeComparator{}
}

// CompareSnapshots compares two snapshots and returns detected changes
func (tc *TreeComparator) CompareSnapshots(oldTree, newTree *FileTree) []*FileChange {
	if oldTree == nil || newTree == nil {
		logger.L().Warning("Cannot compare snapshots: one or both are nil")
		return nil
	}

	var changes []*FileChange

	// Phase 1: Collect all basic changes (CREATE, DELETE, MODIFY, CHMOD)
	// Start with empty path components for root
	changes = append(changes, tc.compareNodes(oldTree.GetRoot(), newTree.GetRoot(), []string{}, 0)...)

	// Phase 2: Analyze changes to detect MOVE and RENAME operations
	changes = tc.detectMoveAndRenameOperations(changes)

	return changes
}

// detectMoveAndRenameOperations analyzes changes to detect MOVE and RENAME operations
func (tc *TreeComparator) detectMoveAndRenameOperations(changes []*FileChange) []*FileChange {
	var result []*FileChange
	var creates []*FileChange
	var deletes []*FileChange

	// Separate creates and deletes for analysis
	for _, change := range changes {
		switch change.Type {
		case ChangeTypeCreate:
			creates = append(creates, change)
		case ChangeTypeDelete:
			deletes = append(deletes, change)
		default:
			// Keep other changes as-is
			result = append(result, change)
		}
	}

	// Try to match deletes with creates to identify moves/renames
	matchedCreates := make(map[*FileChange]bool)
	matchedDeletes := make(map[*FileChange]bool)

	for _, deleteChange := range deletes {
		for _, createChange := range creates {
			if matchedCreates[createChange] || matchedDeletes[deleteChange] {
				continue
			}

			// Check if this could be a move/rename operation
			if tc.couldBeMoveOrRename(deleteChange.OldNode, createChange.NewNode) {
				// Determine if it's a move or rename based on directory changes
				if tc.isRenameOperation(deleteChange.OldNode, createChange.NewNode) {
					// Create a RENAME change
					result = append(result, &FileChange{
						Type:      ChangeTypeRename,
						Path:      createChange.NewNode.Path,
						OldNode:   deleteChange.OldNode,
						NewNode:   createChange.NewNode,
						Timestamp: time.Now(),
					})
				} else {
					// Create a MOVE change
					result = append(result, &FileChange{
						Type:      ChangeTypeMove,
						Path:      createChange.NewNode.Path,
						OldNode:   deleteChange.OldNode,
						NewNode:   createChange.NewNode,
						Timestamp: time.Now(),
					})
				}

				matchedCreates[createChange] = true
				matchedDeletes[deleteChange] = true
				break
			}
		}
	}

	// Add unmatched creates and deletes
	for _, createChange := range creates {
		if !matchedCreates[createChange] {
			result = append(result, createChange)
		}
	}

	for _, deleteChange := range deletes {
		if !matchedDeletes[deleteChange] {
			result = append(result, deleteChange)
		}
	}

	return result
}

// compareNodes recursively compares two nodes and their children
func (tc *TreeComparator) compareNodes(oldNode, newNode *FileNode, pathComponents []string, depth int) []*FileChange {
	var changes []*FileChange

	// Check recursion depth limit to prevent stack overflow
	if depth > MaxRecursionDepth {
		currentPath := buildPathFromComponents(pathComponents)
		logger.L().Warning("Maximum recursion depth exceeded", helpers.String("path", currentPath), helpers.Int("depth", depth))
		return changes
	}

	// Handle nil nodes
	if oldNode == nil && newNode == nil {
		return changes
	}

	if oldNode == nil {
		// New node created
		currentPath := buildPathFromComponents(pathComponents)
		changes = append(changes, &FileChange{
			Type:      ChangeTypeCreate,
			Path:      currentPath,
			OldNode:   nil,
			NewNode:   newNode,
			Timestamp: time.Now(),
		})
		// Recurse into children
		for _, child := range newNode.GetChildren() {
			childPathComponents := append(pathComponents, child.Name)
			changes = append(changes, tc.compareNodes(nil, child, childPathComponents, depth+1)...)
		}
		return changes
	}

	if newNode == nil {
		// Node deleted
		currentPath := buildPathFromComponents(pathComponents)
		changes = append(changes, &FileChange{
			Type:      ChangeTypeDelete,
			Path:      currentPath,
			OldNode:   oldNode,
			NewNode:   nil,
			Timestamp: time.Now(),
		})
		// Recurse into children
		for _, child := range oldNode.GetChildren() {
			childPathComponents := append(pathComponents, child.Name)
			changes = append(changes, tc.compareNodes(child, nil, childPathComponents, depth+1)...)
		}
		return changes
	}

	// Both nodes exist, compare them
	if tc.nodesAreDifferent(oldNode, newNode) {
		currentPath := buildPathFromComponents(pathComponents)
		// Check if this is a CHMOD (permission change only) - check this first
		if tc.isChmodChange(oldNode, newNode) {
			changes = append(changes, &FileChange{
				Type:      ChangeTypeChmod,
				Path:      currentPath,
				OldNode:   oldNode,
				NewNode:   newNode,
				Timestamp: time.Now(),
			})
		} else if tc.isMoveOperation(oldNode, newNode) {
			// Check if this might be a move operation
			changes = append(changes, &FileChange{
				Type:      ChangeTypeMove,
				Path:      currentPath,
				OldNode:   oldNode,
				NewNode:   newNode,
				Timestamp: time.Now(),
			})
		} else {
			// Regular modify
			changes = append(changes, &FileChange{
				Type:      ChangeTypeModify,
				Path:      currentPath,
				OldNode:   oldNode,
				NewNode:   newNode,
				Timestamp: time.Now(),
			})
		}
	}

	// Compare children
	oldChildren := oldNode.GetChildren()
	newChildren := newNode.GetChildren()

	// Check for deleted children
	for name, oldChild := range oldChildren {
		if _, exists := newChildren[name]; !exists {
			childPathComponents := append(pathComponents, name)
			changes = append(changes, tc.compareNodes(oldChild, nil, childPathComponents, depth+1)...)
		}
	}

	// Check for new children
	for name, newChild := range newChildren {
		if _, exists := oldChildren[name]; !exists {
			childPathComponents := append(pathComponents, name)
			changes = append(changes, tc.compareNodes(nil, newChild, childPathComponents, depth+1)...)
		}
	}

	// Recurse into existing children
	for name, oldChild := range oldChildren {
		if newChild, exists := newChildren[name]; exists {
			childPathComponents := append(pathComponents, name)
			changes = append(changes, tc.compareNodes(oldChild, newChild, childPathComponents, depth+1)...)
		}
	}

	return changes
}

// nodesAreDifferent checks if two nodes have different content/metadata
func (tc *TreeComparator) nodesAreDifferent(oldNode, newNode *FileNode) bool {
	// Compare basic properties
	if oldNode.IsDir != newNode.IsDir {
		return true
	}

	if !oldNode.IsDir {
		// For files, compare size, modification time, and permissions
		if oldNode.Size != newNode.Size {
			return true
		}
		if oldNode.Mode != newNode.Mode {
			return true
		}
		if oldNode.Uid != newNode.Uid {
			return true
		}
		if oldNode.Gid != newNode.Gid {
			return true
		}
		if !oldNode.Mtime.Equal(newNode.Mtime) {
			return true
		}
		if !oldNode.Ctime.Equal(newNode.Ctime) {
			return true
		}
		if oldNode.Inode != newNode.Inode {
			return true
		}
		if oldNode.Device != newNode.Device {
			return true
		}
	}

	return false
}

// isMoveOperation checks if a change might be a move operation
func (tc *TreeComparator) isMoveOperation(oldNode, newNode *FileNode) bool {
	// This is a simplified heuristic - in practice, you might want more sophisticated logic
	// For now, we'll consider it a move if the nodes have the same size and similar modification times
	if oldNode.IsDir != newNode.IsDir {
		return false
	}

	if !oldNode.IsDir {
		// For files, check if size and mtime are very similar (within 1 second)
		if oldNode.Size != newNode.Size {
			return false
		}
		timeDiff := oldNode.Mtime.Sub(newNode.Mtime)
		if timeDiff < -time.Second || timeDiff > time.Second {
			return false
		}
	}

	return true
}

// isChmodChange checks if a change is a CHMOD (permission) change only
func (tc *TreeComparator) isChmodChange(oldNode, newNode *FileNode) bool {
	// For files, check if only the mode (permissions) has changed
	if oldNode.IsDir != newNode.IsDir {
		return false
	}

	if !oldNode.IsDir {
		// Check if only mode is different, everything else is the same
		if oldNode.Size != newNode.Size {
			return false
		}
		if oldNode.Inode != newNode.Inode {
			return false
		}
		if oldNode.Device != newNode.Device {
			return false
		}
		// Allow small time differences for CHMOD (os.Chmod updates mtime)
		timeDiff := oldNode.Mtime.Sub(newNode.Mtime)
		if timeDiff < -time.Second || timeDiff > time.Second {
			return false
		}
		if oldNode.Uid != newNode.Uid {
			return false
		}
		if oldNode.Gid != newNode.Gid {
			return false
		}
		// If we get here, only mode is different
		return oldNode.Mode != newNode.Mode
	}

	return false
}

// ConvertToFimEvents converts file changes to FIM events
func (tc *TreeComparator) ConvertToFimEvents(changes []*FileChange, hostPath string) []fimtypes.FimEvent {
	var events []fimtypes.FimEvent

	for _, change := range changes {
		event := tc.convertChangeToFimEvent(change, hostPath)
		if event != nil {
			events = append(events, event)
		}
	}

	return events
}

// convertChangeToFimEvent converts a single change to a FIM event
func (tc *TreeComparator) convertChangeToFimEvent(change *FileChange, hostPath string) fimtypes.FimEvent {
	var event fimtypes.FimEventImpl

	// Set basic event properties
	event.Timestamp = change.Timestamp

	// Determine event type and strip hostPath prefix from paths
	switch change.Type {
	case ChangeTypeCreate:
		event.EventType = fimtypes.FimEventTypeCreate
		event.Path = tc.stripHostPath(change.NewNode.Path, hostPath)
		tc.populateEventMetadata(&event, change.NewNode)
	case ChangeTypeModify:
		event.EventType = fimtypes.FimEventTypeChange
		event.Path = tc.stripHostPath(change.NewNode.Path, hostPath)
		tc.populateEventMetadata(&event, change.NewNode)
	case ChangeTypeDelete:
		event.EventType = fimtypes.FimEventTypeRemove
		event.Path = tc.stripHostPath(change.OldNode.Path, hostPath)
		tc.populateEventMetadata(&event, change.OldNode)
	case ChangeTypeMove:
		event.EventType = fimtypes.FimEventTypeMove
		event.Path = tc.stripHostPath(change.NewNode.Path, hostPath)
		tc.populateEventMetadata(&event, change.NewNode)
	case ChangeTypeChmod:
		event.EventType = fimtypes.FimEventTypeChmod
		event.Path = tc.stripHostPath(change.NewNode.Path, hostPath)
		tc.populateEventMetadata(&event, change.NewNode)
	case ChangeTypeRename:
		event.EventType = fimtypes.FimEventTypeRename
		event.Path = tc.stripHostPath(change.NewNode.Path, hostPath)
		tc.populateEventMetadata(&event, change.NewNode)
	}

	// Set host information
	event.HostName = tc.getHostInfo()
	event.AgentId = "kubescape-node-agent"

	return &event
}

// populateEventMetadata populates event metadata from a file node
func (tc *TreeComparator) populateEventMetadata(event *fimtypes.FimEventImpl, node *FileNode) {
	event.FileSize = node.Size
	event.FileInode = node.Inode
	event.FileDevice = node.Device
	event.FileMtime = node.Mtime
	event.FileCtime = node.Ctime
	event.Uid = node.Uid
	event.Gid = node.Gid
	event.Mode = node.Mode

	// Try to get file hash for files
	if !node.IsDir {
		event.FileHash = tc.calculateFileHash(node.Path)
	}
}

// calculateFileHash calculates SHA256 hash of a file
func (tc *TreeComparator) calculateFileHash(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		logger.L().Debug("Could not open file for hashing",
			helpers.String("path", filePath),
			helpers.Error(err))
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		logger.L().Debug("Could not read file for hashing",
			helpers.String("path", filePath),
			helpers.Error(err))
		return ""
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

// stripHostPath removes the hostPath prefix from a file path
func (tc *TreeComparator) stripHostPath(filePath, hostPath string) string {
	if hostPath == "" || hostPath == "/" {
		return filePath
	}

	// Ensure both paths end with / for consistent comparison
	normalizedFilePath := filePath
	normalizedHostPath := hostPath

	if !strings.HasSuffix(normalizedFilePath, "/") {
		normalizedFilePath += "/"
	}
	if !strings.HasSuffix(normalizedHostPath, "/") {
		normalizedHostPath += "/"
	}

	// Check if the file path starts with the host path
	if strings.HasPrefix(normalizedFilePath, normalizedHostPath) {
		// Remove the host path prefix but keep any leading slash
		stripped := strings.TrimPrefix(normalizedFilePath, normalizedHostPath)
		if !strings.HasPrefix(stripped, "/") {
			stripped = "/" + stripped
		}
		// Remove only the trailing slash
		return strings.TrimRight(stripped, "/")
	}

	// If no prefix match, return the original path
	return filePath
}

// getHostInfo gets basic host information
func (tc *TreeComparator) getHostInfo() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// couldBeMoveOrRename checks if two nodes could represent a move/rename operation
func (tc *TreeComparator) couldBeMoveOrRename(oldNode, newNode *FileNode) bool {
	if oldNode == nil || newNode == nil {
		return false
	}

	// Both nodes must be the same type (file or directory)
	if oldNode.IsDir != newNode.IsDir {
		return false
	}

	if !oldNode.IsDir {
		// For files, check if content is the same
		if oldNode.Size != newNode.Size {
			return false
		}
		// Allow small time differences for move/rename operations
		timeDiff := oldNode.Mtime.Sub(newNode.Mtime)
		if timeDiff < -time.Second || timeDiff > time.Second {
			return false
		}
		// Check if inode and device are the same (same filesystem)
		if oldNode.Inode != newNode.Inode {
			return false
		}
		if oldNode.Device != newNode.Device {
			return false
		}
	}

	return true
}

// isRenameOperation determines if a change is a rename (same directory) vs move (different directory)
func (tc *TreeComparator) isRenameOperation(oldNode, newNode *FileNode) bool {
	if oldNode == nil || newNode == nil {
		return false
	}

	// Get parent directories
	oldParent := filepath.Dir(oldNode.Path)
	newParent := filepath.Dir(newNode.Path)

	// If parent directories are the same, it's a rename
	return oldParent == newParent
}
