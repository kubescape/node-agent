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
	creator.processMap.Set(testPID, testProcess)

	// Create a child process
	childPID := uint32(456)
	childProcess := &apitypes.Process{
		PID:         childPID,
		PPID:        testPID,
		Comm:        "child-process",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	creator.processMap.Set(childPID, childProcess)
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
	assert.NotNil(t, creator.processMap.Get(testPID))
	assert.NotNil(t, creator.processMap.Get(childPID))

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
	assert.Nil(t, creator.processMap.Get(testPID))
	assert.NotNil(t, creator.processMap.Get(childPID)) // Child should still exist but be reparented

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
	creator.processMap.Set(testPID, testProcess)

	// Create exit event
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         testPID,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}

	// Add to pending cleanup
	creator.exitCleanup.AddPendingExit(exitEvent, []*apitypes.Process{})

	// Verify process is still in the map
	assert.NotNil(t, creator.processMap.Get(testPID))

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
	assert.Nil(t, creator.processMap.Get(testPID))
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
	_, exists := creator.exitCleanup.pendingExits.Load(uint32(999))
	assert.False(t, exists)

	// Trigger cleanup manually (with proper mutex locking)
	creator.mutex.Lock()
	creator.exitCleanup.performCleanup()
	creator.mutex.Unlock()

	// Verify it was removed from pending exits (should still not be present)
	_, exists = creator.exitCleanup.pendingExits.Load(uint32(999))
	assert.False(t, exists)
}

func TestExitCleanupManager_AddPendingExit_ProcessExists(t *testing.T) {
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
	creator.processMap.Set(testPID, testProcess)

	// Create child processes
	child1 := &apitypes.Process{
		PID:         456,
		PPID:        testPID,
		Comm:        "child1",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	child2 := &apitypes.Process{
		PID:         789,
		PPID:        testPID,
		Comm:        "child2",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	children := []*apitypes.Process{child1, child2}

	// Create exit event
	startTime := uint64(time.Now().UnixNano())
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         testPID,
		StartTimeNs: startTime,
	}

	// Record time before adding
	beforeTime := time.Now()

	// Add to pending cleanup
	creator.exitCleanup.AddPendingExit(exitEvent, children)

	// Verify it was added to pendingExits
	value, exists := creator.exitCleanup.pendingExits.Load(testPID)
	assert.True(t, exists)

	// Verify the pending exit has correct fields
	pending := value.(*pendingExit)
	assert.Equal(t, testPID, pending.PID)
	assert.Equal(t, startTime, pending.StartTimeNs)
	assert.Equal(t, len(children), len(pending.Children))
	assert.Equal(t, children, pending.Children)

	// Verify timestamp is reasonable (within 1 second of when we called it)
	assert.WithinDuration(t, beforeTime, pending.Timestamp, 1*time.Second)
}

func TestExitCleanupManager_AddPendingExit_ProcessNotExists(t *testing.T) {
	// Create a process tree creator
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := NewProcessTreeCreator(containerTree).(*processTreeCreatorImpl)
	defer creator.Stop()

	// Create exit event for a process that doesn't exist
	testPID := uint32(999)
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         testPID,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}

	// Create some children
	child1 := &apitypes.Process{
		PID:         456,
		PPID:        testPID,
		Comm:        "child1",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	children := []*apitypes.Process{child1}

	// Add to pending cleanup
	creator.exitCleanup.AddPendingExit(exitEvent, children)

	// Verify it was NOT added to pendingExits
	_, exists := creator.exitCleanup.pendingExits.Load(testPID)
	assert.False(t, exists)

	// Check that the map is empty
	count := 0
	creator.exitCleanup.pendingExits.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	assert.Equal(t, 0, count)
}

func TestExitCleanupManager_AddPendingExit_WithNoChildren(t *testing.T) {
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
	creator.processMap.Set(testPID, testProcess)

	// Create exit event
	startTime := uint64(time.Now().UnixNano())
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         testPID,
		StartTimeNs: startTime,
	}

	// Add to pending cleanup with no children
	creator.exitCleanup.AddPendingExit(exitEvent, []*apitypes.Process{})

	// Verify it was added to pendingExits
	value, exists := creator.exitCleanup.pendingExits.Load(testPID)
	assert.True(t, exists)

	// Verify the pending exit has correct fields
	pending := value.(*pendingExit)
	assert.Equal(t, testPID, pending.PID)
	assert.Equal(t, startTime, pending.StartTimeNs)
	assert.Empty(t, pending.Children)
}

func TestExitCleanupManager_AddPendingExit_MultipleAdditions(t *testing.T) {
	// Create a process tree creator
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := NewProcessTreeCreator(containerTree).(*processTreeCreatorImpl)
	defer creator.Stop()

	// Create multiple test processes
	pids := []uint32{100, 200, 300}
	for _, pid := range pids {
		testProcess := &apitypes.Process{
			PID:         pid,
			PPID:        1,
			Comm:        "test-process",
			ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
		}
		creator.processMap.Set(pid, testProcess)
	}

	// Add all processes to pending cleanup
	for _, pid := range pids {
		exitEvent := feeder.ProcessEvent{
			Type:        feeder.ExitEvent,
			PID:         pid,
			StartTimeNs: uint64(time.Now().UnixNano()),
		}
		creator.exitCleanup.AddPendingExit(exitEvent, []*apitypes.Process{})
	}

	// Verify all were added to pendingExits
	count := 0
	creator.exitCleanup.pendingExits.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	assert.Equal(t, len(pids), count)

	for _, pid := range pids {
		_, exists := creator.exitCleanup.pendingExits.Load(pid)
		assert.True(t, exists)
	}
}

func TestExitCleanupManager_AddPendingExit_ForceCleanup(t *testing.T) {
	// Create a process tree creator
	containerTree := containerprocesstree.NewContainerProcessTree()
	creator := NewProcessTreeCreator(containerTree).(*processTreeCreatorImpl)
	defer creator.Stop()

	// Create maxPendingExits processes to trigger force cleanup
	numProcesses := maxPendingExits
	for i := 0; i < numProcesses; i++ {
		pid := uint32(i + 1)
		testProcess := &apitypes.Process{
			PID:         pid,
			PPID:        1,
			Comm:        "test-process",
			ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
		}
		creator.processMap.Set(pid, testProcess)
	}

	// Add processes one by one - the last one should trigger force cleanup
	for i := 0; i < numProcesses; i++ {
		pid := uint32(i + 1)
		exitEvent := feeder.ProcessEvent{
			Type:        feeder.ExitEvent,
			PID:         pid,
			StartTimeNs: uint64(time.Now().UnixNano()),
		}
		creator.exitCleanup.AddPendingExit(exitEvent, []*apitypes.Process{})
	}

	// After adding maxPendingExits processes, force cleanup should have been triggered
	// All processes should be removed from pendingExits due to forceCleanup
	count := 0
	creator.exitCleanup.pendingExits.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	assert.Equal(t, 0, count)

	// All processes should also be removed from processMap
	for i := 0; i < numProcesses; i++ {
		pid := uint32(i + 1)
		assert.Nil(t, creator.processMap.Get(pid))
	}
}

func TestExitCleanupManager_AddPendingExit_OverwriteExisting(t *testing.T) {
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
	creator.processMap.Set(testPID, testProcess)

	// Add first exit event
	firstStartTime := uint64(time.Now().UnixNano())
	firstExitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         testPID,
		StartTimeNs: firstStartTime,
	}
	firstChild := &apitypes.Process{PID: 456, PPID: testPID, Comm: "child1"}
	creator.exitCleanup.AddPendingExit(firstExitEvent, []*apitypes.Process{firstChild})

	// Verify first addition
	value, exists := creator.exitCleanup.pendingExits.Load(testPID)
	assert.True(t, exists)
	firstPending := value.(*pendingExit)
	assert.Equal(t, firstStartTime, firstPending.StartTimeNs)
	assert.Len(t, firstPending.Children, 1)

	// Add second exit event (should overwrite the first one)
	time.Sleep(1 * time.Millisecond) // Small delay to ensure different timestamp
	secondStartTime := uint64(time.Now().UnixNano())
	secondExitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         testPID,
		StartTimeNs: secondStartTime,
	}
	secondChild := &apitypes.Process{PID: 789, PPID: testPID, Comm: "child2"}
	creator.exitCleanup.AddPendingExit(secondExitEvent, []*apitypes.Process{secondChild})

	// Verify second addition overwrote the first
	value, exists = creator.exitCleanup.pendingExits.Load(testPID)
	assert.True(t, exists)
	secondPending := value.(*pendingExit)
	assert.Equal(t, secondStartTime, secondPending.StartTimeNs)
	assert.Len(t, secondPending.Children, 1)
	assert.Equal(t, secondChild, secondPending.Children[0])

	// Verify we still have only one pending exit for this PID
	count := 0
	creator.exitCleanup.pendingExits.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	assert.Equal(t, 1, count)
}
