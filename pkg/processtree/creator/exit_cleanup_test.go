package processtreecreator

import (
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/stretchr/testify/assert"
)

func TestExitCleanupManager(t *testing.T) {
	// Create a process tree creator
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := NewProcessTreeCreator(containerTree).(*processTreeCreatorImpl)
	defer creator.Stop()

	// Create a test process
	testPID := uint32(123)
	testProcess := &apitypes.Process{
		PID:         testPID,
		PPID:        1,
		Comm:        "test-process",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	creator.processMap[testPID] = testProcess

	// Create a child process
	childPID := uint32(456)
	childProcess := &apitypes.Process{
		PID:         childPID,
		PPID:        testPID,
		Comm:        "child-process",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	creator.processMap[childPID] = childProcess
	testProcess.ChildrenMap[apitypes.CommPID{Comm: childProcess.Comm, PID: childPID}] = childProcess

	// Create exit event
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         testPID,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}

	// Add to pending cleanup
	creator.exitCleanup.AddPendingExit(exitEvent, []*apitypes.Process{childProcess})

	// Verify process is still in the map
	assert.Contains(t, creator.processMap, testPID)
	assert.Contains(t, creator.processMap, childPID)

	// Wait for cleanup (with a shorter delay for testing)
	creator.exitCleanup.cleanupDelay = 100 * time.Millisecond
	creator.exitCleanup.cleanupInterval = 50 * time.Millisecond

	// Wait a bit longer than the cleanup delay
	time.Sleep(200 * time.Millisecond)

	// Trigger cleanup manually (with proper mutex locking)
	creator.mutex.Lock()
	creator.exitCleanup.performCleanup()
	creator.mutex.Unlock()

	// Verify process was removed
	assert.NotContains(t, creator.processMap, testPID)
	assert.Contains(t, creator.processMap, childPID) // Child should still exist but be reparented

	// Verify child was reparented to init (PID 1)
	assert.Equal(t, uint32(1), childProcess.PPID)
}

func TestExitCleanupManager_NoChildren(t *testing.T) {
	// Create a process tree creator
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := NewProcessTreeCreator(containerTree).(*processTreeCreatorImpl)
	defer creator.Stop()

	// Create a test process with no children
	testPID := uint32(123)
	testProcess := &apitypes.Process{
		PID:         testPID,
		PPID:        1,
		Comm:        "test-process",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	creator.processMap[testPID] = testProcess

	// Create exit event
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         testPID,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}

	// Add to pending cleanup
	creator.exitCleanup.AddPendingExit(exitEvent, []*apitypes.Process{})

	// Verify process is still in the map
	assert.Contains(t, creator.processMap, testPID)

	// Wait for cleanup (with a shorter delay for testing)
	creator.exitCleanup.cleanupDelay = 100 * time.Millisecond
	creator.exitCleanup.cleanupInterval = 50 * time.Millisecond

	// Wait a bit longer than the cleanup delay
	time.Sleep(200 * time.Millisecond)

	// Trigger cleanup manually (with proper mutex locking)
	creator.mutex.Lock()
	creator.exitCleanup.performCleanup()
	creator.mutex.Unlock()

	// Verify process was removed
	assert.NotContains(t, creator.processMap, testPID)
}

func TestExitCleanupManager_ProcessAlreadyRemoved(t *testing.T) {
	// Create a process tree creator
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := NewProcessTreeCreator(containerTree).(*processTreeCreatorImpl)
	defer creator.Stop()

	// Create exit event for a process that doesn't exist
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         999,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}

	// Add to pending cleanup
	creator.exitCleanup.AddPendingExit(exitEvent, []*apitypes.Process{})

	// Verify it was NOT added to pending exits
	assert.NotContains(t, creator.exitCleanup.pendingExits, uint32(999))

	// Trigger cleanup manually (with proper mutex locking)
	creator.mutex.Lock()
	creator.exitCleanup.performCleanup()
	creator.mutex.Unlock()

	// Verify it was removed from pending exits (should still not be present)
	assert.NotContains(t, creator.exitCleanup.pendingExits, uint32(999))
}
