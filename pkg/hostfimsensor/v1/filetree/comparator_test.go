package filetree

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChmodDetection(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "chmod-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a test file
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

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

	// Wait a bit to ensure different timestamps
	time.Sleep(10 * time.Millisecond)

	// Change file permissions (CHMOD)
	err = os.Chmod(testFile, 0755)
	require.NoError(t, err)

	// Wait a bit more
	time.Sleep(10 * time.Millisecond)

	// Create new snapshot
	newSnapshot, err := manager.CreateSnapshot(tempDir)
	require.NoError(t, err)

	// Compare snapshots
	comparator := NewTreeComparator()
	changes := comparator.CompareSnapshots(oldSnapshot, newSnapshot)

	// Should detect the permission change
	assert.Greater(t, len(changes), 0, "Should detect changes")

	// Check if CHMOD change was detected
	chmodDetected := false
	for _, change := range changes {
		if change.Type == ChangeTypeChmod {
			chmodDetected = true
			break
		}
	}

	assert.True(t, chmodDetected, "Should detect CHMOD change")

	// Convert to FIM events
	events := comparator.ConvertToFimEvents(changes, "")
	assert.Equal(t, len(changes), len(events))

	// Check if CHMOD event was generated
	chmodEventDetected := false
	for _, event := range events {
		if event.GetEventType() == "chmod" {
			chmodEventDetected = true
			break
		}
	}

	assert.True(t, chmodEventDetected, "Should generate CHMOD event")
}

func TestMoveAndRenameDetection(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "move-rename-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test directories
	testDir := filepath.Join(tempDir, "test")
	err = os.Mkdir(testDir, 0755)
	require.NoError(t, err)

	otherDir := filepath.Join(tempDir, "other")
	err = os.Mkdir(otherDir, 0755)
	require.NoError(t, err)

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

	// Wait a bit to ensure different timestamps
	time.Sleep(10 * time.Millisecond)

	// Create a test file
	testFile := filepath.Join(testDir, "testfile.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Wait a bit more
	time.Sleep(10 * time.Millisecond)

	// Create new snapshot
	newSnapshot, err := manager.CreateSnapshot(tempDir)
	require.NoError(t, err)

	// Compare snapshots
	comparator := NewTreeComparator()
	changes := comparator.CompareSnapshots(oldSnapshot, newSnapshot)

	// Should detect the new file
	assert.Greater(t, len(changes), 0, "Should detect changes")

	// Check if CREATE change was detected
	createDetected := false
	for _, change := range changes {
		if change.Type == ChangeTypeCreate {
			createDetected = true
			break
		}
	}
	assert.True(t, createDetected, "Should detect CREATE change")

	// Now test MOVE operation
	oldSnapshot = newSnapshot
	time.Sleep(10 * time.Millisecond)

	// Move file to different directory
	movedFile := filepath.Join(otherDir, "movedfile.txt")
	err = os.Rename(testFile, movedFile)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	// Create new snapshot
	newSnapshot, err = manager.CreateSnapshot(tempDir)
	require.NoError(t, err)

	// Compare snapshots
	changes = comparator.CompareSnapshots(oldSnapshot, newSnapshot)

	// Should detect the move operation
	assert.Greater(t, len(changes), 0, "Should detect changes")

	// Check if MOVE change was detected
	moveDetected := false
	for _, change := range changes {
		if change.Type == ChangeTypeMove {
			moveDetected = true
			break
		}
	}
	assert.True(t, moveDetected, "Should detect MOVE change")

	// Test RENAME operation (same directory)
	oldSnapshot = newSnapshot
	time.Sleep(10 * time.Millisecond)

	// Rename file in same directory
	renamedFile := filepath.Join(otherDir, "renamedfile.txt")
	err = os.Rename(movedFile, renamedFile)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	// Create new snapshot
	newSnapshot, err = manager.CreateSnapshot(tempDir)
	require.NoError(t, err)

	// Compare snapshots
	changes = comparator.CompareSnapshots(oldSnapshot, newSnapshot)

	// Should detect the rename operation
	assert.Greater(t, len(changes), 0, "Should detect changes")

	// Check if RENAME change was detected
	renameDetected := false
	for _, change := range changes {
		if change.Type == ChangeTypeRename {
			renameDetected = true
			break
		}
	}
	assert.True(t, renameDetected, "Should detect RENAME change")
}
