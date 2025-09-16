package filetree

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// FileNode represents a file or directory in the tree
type FileNode struct {
	Name     string               // File/directory name
	Path     string               // Full path from root
	IsDir    bool                 // Whether this is a directory
	Size     int64                // File size in bytes
	Inode    uint64               // File inode number
	Device   uint64               // Device number
	Mode     uint32               // File permissions and type
	Uid      uint32               // Owner user ID
	Gid      uint32               // Owner group ID
	Mtime    time.Time            // Last modification time
	Ctime    time.Time            // Last status change time
	Children map[string]*FileNode // Child nodes (for directories)
	Parent   *FileNode            // Parent node
	mu       sync.RWMutex         // Mutex for thread-safe access
}

// FileTree represents the complete file system tree
type FileTree struct {
	Root      *FileNode
	NodeCount int
	mu        sync.RWMutex
}

// NewFileTree creates a new empty file tree
func NewFileTree() *FileTree {
	return &FileTree{
		Root:      nil,
		NodeCount: 0,
	}
}

// NewFileNode creates a new file node
func NewFileNode(name, path string, isDir bool) *FileNode {
	return &FileNode{
		Name:     name,
		Path:     path,
		IsDir:    isDir,
		Children: make(map[string]*FileNode),
	}
}

// AddChild adds a child node to this node
func (n *FileNode) AddChild(child *FileNode) {
	n.mu.Lock()
	defer n.mu.Unlock()

	child.Parent = n
	n.Children[child.Name] = child
}

// GetChild retrieves a child node by name
func (n *FileNode) GetChild(name string) *FileNode {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.Children[name]
}

// HasChild checks if a child with the given name exists
func (n *FileNode) HasChild(name string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()

	_, exists := n.Children[name]
	return exists
}

// RemoveChild removes a child node
func (n *FileNode) RemoveChild(name string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if child, exists := n.Children[name]; exists {
		child.Parent = nil
		delete(n.Children, name)
	}
}

// GetChildren returns a copy of all children
func (n *FileNode) GetChildren() map[string]*FileNode {
	n.mu.RLock()
	defer n.mu.RUnlock()

	children := make(map[string]*FileNode)
	for name, child := range n.Children {
		children[name] = child
	}
	return children
}

// SetMetadata sets the file metadata from os.FileInfo and syscall.Stat_t
func (n *FileNode) SetMetadata(info os.FileInfo, stat *syscall.Stat_t) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.Size = info.Size()
	n.Mode = uint32(info.Mode())
	n.Mtime = info.ModTime()
	n.Ctime = info.ModTime() // Use mtime as fallback for ctime

	if stat != nil {
		n.Inode = stat.Ino
		n.Device = uint64(stat.Dev)
		n.Uid = stat.Uid
		n.Gid = stat.Gid
	}
}

// GetNodeCount returns the total number of nodes in the tree
func (t *FileTree) GetNodeCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.NodeCount
}

// IncrementNodeCount increments the node count
func (t *FileTree) IncrementNodeCount() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.NodeCount++
}

// SetRoot sets the root node of the tree
func (t *FileTree) SetRoot(root *FileNode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Root = root
	if root != nil {
		t.NodeCount = 1 // Root node counts as 1
	}
}

// GetRoot returns the root node
func (t *FileTree) GetRoot() *FileNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Root
}

// FindNode finds a node by path
func (t *FileTree) FindNode(path string) *FileNode {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.Root == nil {
		return nil
	}

	if path == "/" || path == "" {
		return t.Root
	}

	// Split path and traverse
	parts := splitPath(path)
	current := t.Root

	for _, part := range parts {
		if current == nil || !current.IsDir {
			return nil
		}
		current = current.GetChild(part)
	}

	return current
}

// splitPath splits a path into components, handling both absolute and relative paths
func splitPath(path string) []string {
	if path == "/" || path == "" {
		return []string{}
	}

	// Use filepath.Clean to normalize the path
	cleanPath := filepath.Clean(path)
	if cleanPath == "." {
		return []string{}
	}

	// Use strings.Split with filepath.Separator for cross-platform compatibility
	parts := strings.Split(cleanPath, string(filepath.Separator))

	// Filter out empty parts and current directory references
	var result []string
	for _, part := range parts {
		if part != "" && part != "." {
			result = append(result, part)
		}
	}

	return result
}

// Walk traverses the tree and calls the given function for each node
func (t *FileTree) Walk(fn func(*FileNode) error) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.Root == nil {
		return nil
	}

	return t.walkRecursive(t.Root, fn)
}

// walkRecursive recursively walks the tree
func (t *FileTree) walkRecursive(node *FileNode, fn func(*FileNode) error) error {
	if err := fn(node); err != nil {
		return err
	}

	if node.IsDir {
		for _, child := range node.GetChildren() {
			if err := t.walkRecursive(child, fn); err != nil {
				return err
			}
		}
	}

	return nil
}

// Clear removes all nodes from the tree
func (t *FileTree) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.Root = nil
	t.NodeCount = 0
}
