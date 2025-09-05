package filetree

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFileTree(t *testing.T) {
	tree := NewFileTree()
	assert.NotNil(t, tree)
	assert.Nil(t, tree.GetRoot())
	assert.Equal(t, 0, tree.GetNodeCount())
}

func TestNewFileNode(t *testing.T) {
	node := NewFileNode("test", "/test", false)
	assert.NotNil(t, node)
	assert.Equal(t, "test", node.Name)
	assert.Equal(t, "/test", node.Path)
	assert.False(t, node.IsDir)
	assert.NotNil(t, node.Children)
}

func TestFileNodeAddChild(t *testing.T) {
	parent := NewFileNode("parent", "/parent", true)
	child := NewFileNode("child", "/parent/child", false)

	parent.AddChild(child)

	assert.Equal(t, parent, child.Parent)
	assert.Equal(t, child, parent.GetChild("child"))
	assert.True(t, parent.HasChild("child"))
}

func TestFileTreeSetRoot(t *testing.T) {
	tree := NewFileTree()
	root := NewFileNode("root", "/", true)

	tree.SetRoot(root)

	assert.Equal(t, root, tree.GetRoot())
	assert.Equal(t, 1, tree.GetNodeCount())
}

func TestFileTreeFindNode(t *testing.T) {
	tree := NewFileTree()
	root := NewFileNode("root", "/", true)
	child := NewFileNode("child", "/child", false)
	root.AddChild(child)
	tree.SetRoot(root)

	// Test finding root
	found := tree.FindNode("/")
	assert.Equal(t, root, found)

	// Test finding child
	found = tree.FindNode("/child")
	assert.Equal(t, child, found)

	// Test finding non-existent node
	found = tree.FindNode("/nonexistent")
	assert.Nil(t, found)
}

func TestFileTreeWalk(t *testing.T) {
	tree := NewFileTree()
	root := NewFileNode("root", "/", true)
	child1 := NewFileNode("child1", "/child1", false)
	child2 := NewFileNode("child2", "/child2", false)
	root.AddChild(child1)
	root.AddChild(child2)
	tree.SetRoot(root)

	var visited []string
	err := tree.Walk(func(node *FileNode) error {
		visited = append(visited, node.Path)
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, visited, 3)
	assert.Contains(t, visited, "/")
	assert.Contains(t, visited, "/child1")
	assert.Contains(t, visited, "/child2")
}

func TestFileTreeClear(t *testing.T) {
	tree := NewFileTree()
	root := NewFileNode("root", "/", true)
	tree.SetRoot(root)

	assert.Equal(t, 1, tree.GetNodeCount())

	tree.Clear()

	assert.Nil(t, tree.GetRoot())
	assert.Equal(t, 0, tree.GetNodeCount())
}

func TestSnapshotManager(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "snapshot-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create some test files
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Create test configuration
	config := SnapshotConfig{
		MaxScanDepth:    5,
		IncludeHidden:   false,
		ExcludePatterns: []string{"*.tmp"},
		MaxFileSize:     1024 * 1024, // 1MB
		FollowSymlinks:  false,
	}

	// Create snapshot manager
	manager := NewSnapshotManager(1000, config)

	// Create snapshot
	snapshot, err := manager.CreateSnapshot(tempDir)
	require.NoError(t, err)
	require.NotNil(t, snapshot)

	// Verify snapshot was created
	assert.Greater(t, snapshot.GetNodeCount(), 0)

	// Test snapshot rotation
	oldSnapshot := manager.GetCurrentSnapshot()
	assert.Equal(t, snapshot, oldSnapshot)

	// Create another snapshot
	newSnapshot, err := manager.CreateSnapshot(tempDir)
	require.NoError(t, err)

	// Verify rotation
	assert.Equal(t, oldSnapshot, manager.GetPreviousSnapshot())
	assert.Equal(t, newSnapshot, manager.GetCurrentSnapshot())
}

func TestTreeComparator(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "comparator-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create initial snapshot
	config := SnapshotConfig{
		MaxScanDepth:    5,
		IncludeHidden:   false,
		ExcludePatterns: []string{},
		MaxFileSize:     1024 * 1024,
		FollowSymlinks:  false,
	}

	manager := NewSnapshotManager(1000, config)
	oldSnapshot, err := manager.CreateSnapshot(tempDir)
	require.NoError(t, err)

	// Create a new file
	testFile := filepath.Join(tempDir, "newfile.txt")
	err = os.WriteFile(testFile, []byte("new content"), 0644)
	require.NoError(t, err)

	// Create new snapshot
	newSnapshot, err := manager.CreateSnapshot(tempDir)
	require.NoError(t, err)

	// Compare snapshots
	comparator := NewTreeComparator()
	changes := comparator.CompareSnapshots(oldSnapshot, newSnapshot)

	// Should detect the new file
	assert.Greater(t, len(changes), 0)

	// Convert to FIM events
	events := comparator.ConvertToFimEvents(changes, "")
	assert.Equal(t, len(changes), len(events))
}
