package filetree

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// SnapshotManager manages file tree snapshots with size constraints
type SnapshotManager struct {
	maxNodes         int
	currentSnapshot  *FileTree
	previousSnapshot *FileTree
	config           SnapshotConfig
}

// SnapshotConfig holds configuration for snapshot creation
type SnapshotConfig struct {
	MaxScanDepth    int      // Maximum directory depth to scan
	IncludeHidden   bool     // Whether to include hidden files
	ExcludePatterns []string // Glob patterns to exclude
	MaxFileSize     int64    // Maximum file size to track
	FollowSymlinks  bool     // Whether to follow symbolic links
}

// NewSnapshotManager creates a new snapshot manager
func NewSnapshotManager(maxNodes int, config SnapshotConfig) *SnapshotManager {
	return &SnapshotManager{
		maxNodes: maxNodes,
		config:   config,
	}
}

// CreateSnapshot creates a new snapshot from the given root path
func (sm *SnapshotManager) CreateSnapshot(rootPath string) (*FileTree, error) {
	logger.L().Debug("Creating new snapshot", helpers.String("root", rootPath))

	tree := NewFileTree()

	// Build tree with node counting
	err := sm.buildTreeRecursive(rootPath, tree, 0, nil)
	if err != nil {
		logger.L().Error("Failed to build tree",
			helpers.String("root", rootPath),
			helpers.Error(err))
		return nil, err
	}

	// Check size limits
	if tree.GetNodeCount() > sm.maxNodes {
		logger.L().Error("Snapshot exceeds maximum node limit",
			helpers.Int("current", tree.GetNodeCount()),
			helpers.Int("limit", sm.maxNodes),
			helpers.String("path", rootPath))

		// Clean up current snapshot
		sm.currentSnapshot = nil

		return nil, fmt.Errorf("snapshot node count %d exceeds limit %d", tree.GetNodeCount(), sm.maxNodes)
	}

	logger.L().Debug("Snapshot created successfully",
		helpers.Int("nodes", tree.GetNodeCount()),
		helpers.String("root", rootPath))

	// Rotate snapshots
	sm.previousSnapshot = sm.currentSnapshot
	sm.currentSnapshot = tree

	return tree, nil
}

// buildTreeRecursive recursively builds the file tree
func (sm *SnapshotManager) buildTreeRecursive(path string, tree *FileTree, depth int, parentNode *FileNode) error {
	// Check depth limit
	if depth > sm.config.MaxScanDepth {
		return nil
	}

	// Check if we should exclude this path
	if sm.shouldExclude(path) {
		return nil
	}

	// Get file info
	info, err := os.Lstat(path)
	if err != nil {
		// Log but continue - some files might be inaccessible
		logger.L().Debug("Could not stat file, skipping",
			helpers.String("path", path),
			helpers.Error(err))
		return nil
	}

	// Handle symlinks
	if info.Mode()&os.ModeSymlink != 0 {
		if !sm.config.FollowSymlinks {
			return nil
		}
		// Follow symlink
		target, err := os.Readlink(path)
		if err != nil {
			logger.L().Debug("Could not read symlink, skipping",
				helpers.String("path", path),
				helpers.Error(err))
			return nil
		}
		// Resolve relative symlinks
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		info, err = os.Stat(target)
		if err != nil {
			logger.L().Debug("Could not stat symlink target, skipping",
				helpers.String("path", path),
				helpers.String("target", target),
				helpers.Error(err))
			return nil
		}
	}

	// Check file size limit
	if !info.IsDir() && info.Size() > sm.config.MaxFileSize {
		logger.L().Debug("File too large, skipping",
			helpers.String("path", path),
			helpers.Int("size", int(info.Size())),
			helpers.Int("limit", int(sm.config.MaxFileSize)))
		return nil
	}

	// Create node
	nodeName := filepath.Base(path)
	if depth == 0 {
		nodeName = "/"
	}

	node := NewFileNode(nodeName, path, info.IsDir())

	// Get detailed stat info
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		node.SetMetadata(info, stat)
	} else {
		// Fallback for non-Unix systems
		node.SetMetadata(info, nil)
	}

	// Add to tree
	if depth == 0 {
		tree.SetRoot(node)
	} else if parentNode != nil {
		// Add as child of parent node
		parentNode.AddChild(node)
		tree.IncrementNodeCount()
	}

	// Recurse into directories
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			logger.L().Debug("Could not read directory, skipping",
				helpers.String("path", path),
				helpers.Error(err))
			return nil
		}

		for _, entry := range entries {
			// Check hidden files
			if !sm.config.IncludeHidden && strings.HasPrefix(entry.Name(), ".") {
				continue
			}

			entryPath := filepath.Join(path, entry.Name())

			// Check node count limit during building
			if tree.GetNodeCount() >= sm.maxNodes {
				return fmt.Errorf("reached maximum node limit %d during tree building", sm.maxNodes)
			}

			err := sm.buildTreeRecursive(entryPath, tree, depth+1, node)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// shouldExclude checks if a path should be excluded based on patterns
func (sm *SnapshotManager) shouldExclude(path string) bool {
	baseName := filepath.Base(path)

	for _, pattern := range sm.config.ExcludePatterns {
		if matched, _ := filepath.Match(pattern, baseName); matched {
			return true
		}
	}

	return false
}

// GetCurrentSnapshot returns the current snapshot
func (sm *SnapshotManager) GetCurrentSnapshot() *FileTree {
	return sm.currentSnapshot
}

// GetPreviousSnapshot returns the previous snapshot
func (sm *SnapshotManager) GetPreviousSnapshot() *FileTree {
	return sm.previousSnapshot
}

// HasPreviousSnapshot checks if there's a previous snapshot
func (sm *SnapshotManager) HasPreviousSnapshot() bool {
	return sm.previousSnapshot != nil
}

// ClearCurrentSnapshot clears the current snapshot
func (sm *SnapshotManager) ClearCurrentSnapshot() {
	sm.currentSnapshot = nil
}

// GetSnapshotStats returns statistics about the snapshots
func (sm *SnapshotManager) GetSnapshotStats() (currentNodes, previousNodes int) {
	if sm.currentSnapshot != nil {
		currentNodes = sm.currentSnapshot.GetNodeCount()
	}
	if sm.previousSnapshot != nil {
		previousNodes = sm.previousSnapshot.GetNodeCount()
	}
	return
}

// Cleanup removes old snapshots to free memory
func (sm *SnapshotManager) Cleanup() {
	if sm.previousSnapshot != nil {
		sm.previousSnapshot.Clear()
		sm.previousSnapshot = nil
	}
}
