package processtreecreator

import (
	"fmt"
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

func TestExitCleanupManager_ForceCleanupAtLimit(t *testing.T) {
	// Create a process tree creator
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := NewProcessTreeCreator(containerTree).(*processTreeCreatorImpl)
	defer creator.Stop()

	// Stop the cleanup loop to avoid race conditions during testing
	creator.exitCleanup.Stop()

	// Create 1000 processes to test the limit
	numProcesses := 1000
	for i := 0; i < numProcesses; i++ {
		pid := uint32(1000 + i)
		process := &apitypes.Process{
			PID:         pid,
			PPID:        1,
			Comm:        fmt.Sprintf("process%d", i),
			ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
		}
		creator.processMap[pid] = process
	}

	// Add 999 exits (just under the limit)
	for i := 0; i < 999; i++ {
		pid := uint32(1000 + i)
		exitEvent := feeder.ProcessEvent{
			Type:        feeder.ExitEvent,
			PID:         pid,
			StartTimeNs: uint64(time.Now().UnixNano()) + uint64(i), // Different start times
		}
		creator.exitCleanup.AddPendingExit(exitEvent, []*apitypes.Process{})
	}

	// Verify we have 999 pending exits
	assert.Equal(t, 999, len(creator.exitCleanup.pendingExits))

	// Add the 1000th exit - this should trigger force cleanup
	pid1000 := uint32(1999)
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         pid1000,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}
	creator.exitCleanup.AddPendingExit(exitEvent, []*apitypes.Process{})

	// Verify that all pending exits were cleaned up
	assert.Equal(t, 1, len(creator.exitCleanup.pendingExits), "Should only have the last added exit")
	assert.Contains(t, creator.exitCleanup.pendingExits, pid1000, "Should have the last added exit")

	// Verify that processes were removed from the process map
	for i := 0; i < 999; i++ {
		pid := uint32(1000 + i)
		assert.NotContains(t, creator.processMap, pid, fmt.Sprintf("Process %d should be removed", pid))
	}
	assert.Contains(t, creator.processMap, pid1000, "Process 1000 should still exist")
}
