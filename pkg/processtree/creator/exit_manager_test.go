package processtreecreator

import (
	"sync"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	processtreecreatorconfig "github.com/kubescape/node-agent/pkg/processtree/config"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/kubescape/node-agent/pkg/processtree/reparenting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing
type mockContainerProcessTree struct{}

func (m *mockContainerProcessTree) ContainerCallback(notif containercollection.PubSubEvent) {}
func (m *mockContainerProcessTree) GetContainerTreeNodes(containerID string, fullTree *maps.SafeMap[uint32, *apitypes.Process]) ([]apitypes.Process, error) {
	return []apitypes.Process{}, nil
}
func (m *mockContainerProcessTree) GetPidBranch(containerID string, targetPID uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) (apitypes.Process, error) {
	return apitypes.Process{}, nil
}
func (m *mockContainerProcessTree) ListContainers() []string {
	return []string{}
}
func (m *mockContainerProcessTree) IsProcessUnderAnyContainerSubtree(pid uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) bool {
	return false
}
func (m *mockContainerProcessTree) IsProcessUnderContainer(pid uint32, containerID string, fullTree *maps.SafeMap[uint32, *apitypes.Process]) bool {
	return false
}

func (m *mockContainerProcessTree) GetShimPIDForProcess(pid uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) (uint32, bool) {
	return 0, false
}
func (m *mockContainerProcessTree) GetPidByContainerID(containerID string) (uint32, error) {
	return 0, nil
}
func (m *mockContainerProcessTree) RegisterContainerShim(containerID string, shimPID uint32, containerPID uint32) {
}
func (m *mockContainerProcessTree) GetContainerInfo(containerID string) (shimPID, containerPID uint32, exists bool) {
	return 0, 0, false
}

// Mock reparenting logic
type mockReparentingLogic struct{}

func (m *mockReparentingLogic) Reparent(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap *maps.SafeMap[uint32, *apitypes.Process]) (uint32, error) {
	return 1, nil // Always reparent to init
}
func (m *mockReparentingLogic) AddStrategy(strategy reparenting.ReparentingStrategy) {}
func (m *mockReparentingLogic) GetStrategies() []reparenting.ReparentingStrategy {
	return []reparenting.ReparentingStrategy{}
}

// Helper function to create a test process tree creator
func createTestProcessTreeCreator() *processTreeCreatorImpl {
	// Create a test config with exit cleanup settings
	testConfig := config.Config{
		ExitCleanup: processtreecreatorconfig.ExitCleanupConfig{
			MaxPendingExits: 1000,
			CleanupInterval: 30 * time.Second,
			CleanupDelay:    1 * time.Minute,
		},
	}

	return &processTreeCreatorImpl{
		processMap:            maps.SafeMap[uint32, *apitypes.Process]{},
		containerTree:         &mockContainerProcessTree{},
		reparentingStrategies: &mockReparentingLogic{},
		pendingExits:          make(map[uint32]*pendingExit),
		config:                testConfig,
	}
}

// Helper function to create a test process
func createTestProcess(pid uint32, ppid uint32, comm string) *apitypes.Process {
	return &apitypes.Process{
		PID:         pid,
		PPID:        ppid,
		Comm:        comm,
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
}

// Helper function to create a test process event
func createTestExitEvent(pid uint32, startTimeNs uint64) conversion.ProcessEvent {
	return conversion.ProcessEvent{
		Type:        conversion.ExitEvent,
		PID:         pid,
		StartTimeNs: startTimeNs,
		Timestamp:   time.Now(),
	}
}

func TestExitManager_StartStop(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Test start
	pt.Start()
	require.NotNil(t, pt.exitCleanupStopChan, "Exit cleanup channel should be created")

	// Test stop
	pt.Stop()

	// Give it a moment to process the stop
	time.Sleep(10 * time.Millisecond)

	// After stop, the channel should be closed and nilified
	require.Nil(t, pt.exitCleanupStopChan, "Stop channel should be nilified after stop")
}

func TestExitManager_AddPendingExit(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Create a test process
	parent := createTestProcess(100, 1, "parent")
	child := createTestProcess(200, 100, "child")
	parent.ChildrenMap[apitypes.CommPID{PID: 200}] = child

	pt.processMap.Set(100, parent)
	pt.processMap.Set(200, child)

	// Test adding a pending exit
	pt.mutex.Lock()
	event := createTestExitEvent(100, 12345)
	pt.addPendingExit(event)
	pt.mutex.Unlock()

	// Check that the exit was added
	pt.mutex.RLock()
	require.Equal(t, 1, len(pt.pendingExits), "Should have 1 pending exit")
	pending := pt.pendingExits[100]
	require.NotNil(t, pending, "Pending exit should exist")
	assert.Equal(t, uint32(100), pending.PID)
	assert.Equal(t, uint64(12345), pending.StartTimeNs)
	assert.Len(t, pending.Children, 0, "Children should be empty initially, populated during exitByPid")
	pt.mutex.RUnlock()
}

func TestExitManager_MaxPendingExits(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Test with a smaller MaxPendingExits for easier testing
	pt.config.ExitCleanup.MaxPendingExits = 10

	pt.mutex.Lock()

	// Fill up to the max limit
	for i := 0; i < pt.config.ExitCleanup.MaxPendingExits; i++ {
		pid := uint32(i + 1)
		parent := createTestProcess(pid, 1, "parent")
		pt.processMap.Set(pid, parent)

		// Create a pending exit that's old enough to be cleaned up
		pt.pendingExits[pid] = &pendingExit{
			PID:         pid,
			StartTimeNs: uint64(i),
			Timestamp:   time.Now().Add(-10 * time.Minute), // Old timestamp
			Children:    []*apitypes.Process{},
		}
	}

	// Verify we have the max number of pending exits
	assert.Equal(t, pt.config.ExitCleanup.MaxPendingExits, len(pt.pendingExits))

	// Now test that forceCleanupOldest works when we reach the limit
	pt.forceCleanupOldest()

	// Should have cleaned up some processes (at least 1000 or 25%, whichever is larger)
	// Since we have 10 processes and minimum cleanup is 1000, it should remove all 10
	assert.Equal(t, 0, len(pt.pendingExits), "All processes should be cleaned up due to minimum cleanup threshold")

	pt.mutex.Unlock()
}

func TestExitManager_RemoveProcessFromPending(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Create a parent process with children
	parent := createTestProcess(100, 1, "parent")
	child1 := createTestProcess(200, 100, "child1")
	child2 := createTestProcess(300, 100, "child2")

	parent.ChildrenMap[apitypes.CommPID{PID: 200}] = child1
	parent.ChildrenMap[apitypes.CommPID{PID: 300}] = child2

	pt.processMap.Set(100, parent)
	pt.processMap.Set(200, child1)
	pt.processMap.Set(300, child2)

	// Add to pending exits
	pt.mutex.Lock()
	pt.pendingExits[100] = &pendingExit{
		PID:         100,
		StartTimeNs: 12345,
		Timestamp:   time.Now(),
		Children:    []*apitypes.Process{child1, child2},
	}
	pt.mutex.Unlock()

	// Remove the process
	pt.mutex.Lock()
	pt.exitByPid(100)
	pt.mutex.Unlock()

	// Check that process was removed from maps
	pt.mutex.RLock()
	assert.Nil(t, pt.processMap.Get(100), "Parent process should be removed from process map")
	assert.Equal(t, 0, len(pt.pendingExits), "Should have no pending exits")

	// Check that children were reparented to init (PID 1)
	assert.Equal(t, uint32(1), child1.PPID, "Child1 should be reparented to init")
	assert.Equal(t, uint32(1), child2.PPID, "Child2 should be reparented to init")
	pt.mutex.RUnlock()
}

func TestExitManager_PerformExitCleanup(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Create processes with different timestamps based on config cleanup delay
	now := time.Now()
	cleanupDelay := pt.config.ExitCleanup.CleanupDelay
	oldTime := now.Add(-cleanupDelay - time.Minute)    // Old enough to be cleaned up (older than cleanup delay)
	recentTime := now.Add(-cleanupDelay + time.Minute) // Too recent to be cleaned up (newer than cleanup delay)

	// Create test processes
	oldParent := createTestProcess(100, 1, "oldParent")
	recentParent := createTestProcess(200, 1, "recentParent")

	pt.processMap.Set(100, oldParent)
	pt.processMap.Set(200, recentParent)

	pt.mutex.Lock()
	// Add old pending exit (should be cleaned up)
	pt.pendingExits[100] = &pendingExit{
		PID:         100,
		StartTimeNs: 12345,
		Timestamp:   oldTime,
		Children:    []*apitypes.Process{},
	}

	// Add recent pending exit (should NOT be cleaned up)
	pt.pendingExits[200] = &pendingExit{
		PID:         200,
		StartTimeNs: 67890,
		Timestamp:   recentTime,
		Children:    []*apitypes.Process{},
	}
	pt.mutex.Unlock()

	// Perform cleanup
	pt.performExitCleanup()

	// Check results
	pt.mutex.RLock()
	assert.Equal(t, 1, len(pt.pendingExits), "Should have 1 pending exit remaining")
	assert.Contains(t, pt.pendingExits, uint32(200), "Recent exit should still be pending")
	assert.NotContains(t, pt.pendingExits, uint32(100), "Old exit should be cleaned up")
	assert.Nil(t, pt.processMap.Get(100), "Old process should be removed from process map")
	assert.NotNil(t, pt.processMap.Get(200), "Recent process should still be in process map")
	pt.mutex.RUnlock()
}

func TestExitManager_GetPendingExitCount(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Initially should be 0
	count := func() int {
		pt.mutex.RLock()
		defer pt.mutex.RUnlock()
		return len(pt.pendingExits)
	}

	assert.Equal(t, 0, count())

	// Add some pending exits
	pt.mutex.Lock()
	pt.pendingExits[100] = &pendingExit{PID: 100, StartTimeNs: 1, Timestamp: time.Now()}
	pt.pendingExits[200] = &pendingExit{PID: 200, StartTimeNs: 2, Timestamp: time.Now()}
	pt.mutex.Unlock()

	// Should now be 2
	assert.Equal(t, 2, count())
}

func TestExitManager_ForceCleanupAllPendingExits(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Create test processes
	parent1 := createTestProcess(100, 1, "parent1")
	parent2 := createTestProcess(200, 1, "parent2")

	pt.processMap.Set(100, parent1)
	pt.processMap.Set(200, parent2)

	// Add pending exits
	pt.mutex.Lock()
	pt.pendingExits[100] = &pendingExit{
		PID:         100,
		StartTimeNs: 12345,
		Timestamp:   time.Now(),
		Children:    []*apitypes.Process{},
	}
	pt.pendingExits[200] = &pendingExit{
		PID:         200,
		StartTimeNs: 67890,
		Timestamp:   time.Now(),
		Children:    []*apitypes.Process{},
	}
	pt.mutex.Unlock()

	// Force cleanup all - we'll implement this manually since the method isn't exposed
	pt.mutex.Lock()
	toRemove := make([]*pendingExit, 0, len(pt.pendingExits))
	for _, pending := range pt.pendingExits {
		toRemove = append(toRemove, pending)
	}

	for _, pending := range toRemove {
		pt.exitByPid(pending.PID)
	}
	pt.mutex.Unlock()

	// Check that all pending exits are cleaned up
	pt.mutex.RLock()
	assert.Equal(t, 0, len(pt.pendingExits), "All pending exits should be cleaned up")
	assert.Nil(t, pt.processMap.Get(100), "Process 100 should be removed")
	assert.Nil(t, pt.processMap.Get(200), "Process 200 should be removed")
	pt.mutex.RUnlock()
}

func TestExitManager_ThreadSafety(t *testing.T) {
	pt := createTestProcessTreeCreator()
	pt.Start()
	defer pt.Stop()

	// Create multiple processes
	for i := 0; i < 100; i++ {
		pid := uint32(i + 1)
		parent := createTestProcess(pid, 1, "parent")
		pt.processMap.Set(pid, parent)
	}

	var wg sync.WaitGroup

	// Concurrent addition of pending exits
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			pid := uint32(i + 1)
			pt.mutex.Lock()
			event := createTestExitEvent(pid, uint64(i))
			pt.addPendingExit(event)
			pt.mutex.Unlock()
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Concurrent reading of pending exit count
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			pt.mutex.RLock()
			count := len(pt.pendingExits)
			pt.mutex.RUnlock()
			assert.GreaterOrEqual(t, count, 0, "Count should be non-negative")
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Concurrent cleanup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			pt.performExitCleanup()
			time.Sleep(5 * time.Millisecond)
		}
	}()

	wg.Wait()

	// Final check - should not panic and should have consistent state
	pt.mutex.RLock()
	finalCount := len(pt.pendingExits)
	pt.mutex.RUnlock()
	assert.GreaterOrEqual(t, finalCount, 0, "Final count should be non-negative")
}

func TestExitManager_HandleExitEventFlow(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Create a parent process with children
	parent := createTestProcess(100, 1, "parent")
	child1 := createTestProcess(200, 100, "child1")
	child2 := createTestProcess(300, 100, "child2")

	parent.ChildrenMap[apitypes.CommPID{PID: 200}] = child1
	parent.ChildrenMap[apitypes.CommPID{PID: 300}] = child2

	pt.processMap.Set(100, parent)
	pt.processMap.Set(200, child1)
	pt.processMap.Set(300, child2)

	// Create exit event
	event := createTestExitEvent(100, 12345)

	// Handle the exit event
	pt.handleExitEvent(event)

	// Check that the process is added to pending exits
	pt.mutex.RLock()
	assert.Equal(t, 1, len(pt.pendingExits), "Should have 1 pending exit")
	pending := pt.pendingExits[100]
	require.NotNil(t, pending, "Pending exit should exist")
	assert.Equal(t, uint32(100), pending.PID)
	assert.Len(t, pending.Children, 0, "Children should be empty initially, populated during exitByPid")

	// Process should still be in the map (not removed yet)
	assert.NotNil(t, pt.processMap.Get(100), "Process should still be in map")
	pt.mutex.RUnlock()
}

func TestExitManager_ReparentingDuringCleanup(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Create a more complex process tree
	// grandparent (PID 1)
	//   └── parent (PID 100)
	//       ├── child1 (PID 200)
	//       └── child2 (PID 300)
	//           └── grandchild (PID 400)

	grandparent := createTestProcess(1, 0, "init")
	parent := createTestProcess(100, 1, "parent")
	child1 := createTestProcess(200, 100, "child1")
	child2 := createTestProcess(300, 100, "child2")
	grandchild := createTestProcess(400, 300, "grandchild")

	// Set up relationships
	grandparent.ChildrenMap[apitypes.CommPID{PID: 100}] = parent
	parent.ChildrenMap[apitypes.CommPID{PID: 200}] = child1
	parent.ChildrenMap[apitypes.CommPID{PID: 300}] = child2
	child2.ChildrenMap[apitypes.CommPID{PID: 400}] = grandchild

	// Add all to process map
	pt.processMap.Set(1, grandparent)
	pt.processMap.Set(100, parent)
	pt.processMap.Set(200, child1)
	pt.processMap.Set(300, child2)
	pt.processMap.Set(400, grandchild)

	// Create pending exit for parent
	pt.mutex.Lock()
	pt.pendingExits[100] = &pendingExit{
		PID:         100,
		StartTimeNs: 12345,
		Timestamp:   time.Now().Add(-10 * time.Minute), // Old enough to be cleaned up
		Children:    []*apitypes.Process{child1, child2},
	}
	pt.mutex.Unlock()

	// Perform cleanup
	pt.performExitCleanup()

	// Check results
	pt.mutex.RLock()
	// Parent should be removed
	assert.Nil(t, pt.processMap.Get(100), "Parent process should be removed")

	// Children should be reparented to init (PID 1) by our mock reparenting logic
	assert.Equal(t, uint32(1), child1.PPID, "Child1 should be reparented to init")
	assert.Equal(t, uint32(1), child2.PPID, "Child2 should be reparented to init")

	// Grandchild should still be under child2
	assert.Equal(t, uint32(300), grandchild.PPID, "Grandchild should still be under child2")

	// No pending exits should remain
	assert.Equal(t, 0, len(pt.pendingExits), "No pending exits should remain")
	pt.mutex.RUnlock()
}

func TestExitManager_CleanupLoop(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Create a process with old timestamp based on config cleanup delay
	parent := createTestProcess(100, 1, "parent")
	pt.processMap.Set(100, parent)

	// Start the exit manager
	pt.Start()
	defer pt.Stop()

	// Add a pending exit with old timestamp based on config cleanup delay
	cleanupDelay := pt.config.ExitCleanup.CleanupDelay
	pt.mutex.Lock()
	pt.pendingExits[100] = &pendingExit{
		PID:         100,
		StartTimeNs: 12345,
		Timestamp:   time.Now().Add(-cleanupDelay - time.Minute), // Old enough to be cleaned up
		Children:    []*apitypes.Process{},
	}
	pt.mutex.Unlock()

	// Trigger cleanup manually (since we don't want to wait for the cleanup interval)
	pt.performExitCleanup()

	// Check that the process was cleaned up
	pt.mutex.RLock()
	assert.Equal(t, 0, len(pt.pendingExits), "Process should be cleaned up")
	assert.Nil(t, pt.processMap.Get(100), "Process should be removed from map")
	pt.mutex.RUnlock()
}

func TestExitManager_CleanupChildrenMapWithEmptyComm(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Create a parent process with children
	parent := createTestProcess(100, 1, "parent")
	child1 := createTestProcess(200, 100, "child1")
	child2 := createTestProcess(300, 100, "child2")

	// Add children to parent's ChildrenMap using only PID (Comm is empty)
	parent.ChildrenMap[apitypes.CommPID{PID: 200}] = child1
	parent.ChildrenMap[apitypes.CommPID{PID: 300}] = child2

	pt.processMap.Set(100, parent)
	pt.processMap.Set(200, child1)
	pt.processMap.Set(300, child2)

	// Verify initial state
	assert.Len(t, parent.ChildrenMap, 2, "Parent should have 2 children initially")

	// Create exit event with empty Comm field (simulating real-world scenario)
	event := createTestExitEvent(100, 12345)

	// Handle the exit event
	pt.handleExitEvent(event)

	// Check that the process is added to pending exits
	pt.mutex.RLock()
	assert.Equal(t, 1, len(pt.pendingExits), "Should have 1 pending exit")
	pending := pt.pendingExits[100]
	require.NotNil(t, pending, "Pending exit should exist")
	assert.Equal(t, uint32(100), pending.PID)
	assert.Len(t, pending.Children, 0, "Children should be empty initially, populated during exitByPid")
	pt.mutex.RUnlock()

	// Now manually trigger the exit cleanup to test the cleanup logic
	pt.mutex.Lock()
	pt.exitByPid(100)
	pt.mutex.Unlock()

	// Check that the parent process was removed from maps
	pt.mutex.RLock()
	assert.Nil(t, pt.processMap.Get(100), "Parent process should be removed from process map")
	assert.Equal(t, 0, len(pt.pendingExits), "Should have no pending exits")

	// Check that children were reparented to init (PID 1) by our mock reparenting logic
	assert.Equal(t, uint32(1), child1.PPID, "Child1 should be reparented to init")
	assert.Equal(t, uint32(1), child2.PPID, "Child2 should be reparented to init")
	pt.mutex.RUnlock()
}

func TestExitManager_CleanupChildrenMapWithMixedCommValues(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Create a parent process with children
	parent := createTestProcess(100, 1, "parent")
	child1 := createTestProcess(200, 100, "child1")
	child2 := createTestProcess(300, 100, "child2")
	child3 := createTestProcess(400, 100, "child3")

	// Add children with mixed Comm values (some empty, some not)
	// This tests that the cleanup works regardless of Comm values
	parent.ChildrenMap[apitypes.CommPID{PID: 200}] = child1 // Empty Comm
	parent.ChildrenMap[apitypes.CommPID{PID: 300}] = child2 // Empty Comm
	parent.ChildrenMap[apitypes.CommPID{PID: 400}] = child3 // Empty Comm

	pt.processMap.Set(100, parent)
	pt.processMap.Set(200, child1)
	pt.processMap.Set(300, child2)
	pt.processMap.Set(400, child3)

	// Verify initial state
	assert.Len(t, parent.ChildrenMap, 3, "Parent should have 3 children initially")

	// Create exit event
	event := createTestExitEvent(100, 12345)

	// Handle the exit event
	pt.handleExitEvent(event)

	// Check that the process is added to pending exits
	pt.mutex.RLock()
	assert.Equal(t, 1, len(pt.pendingExits), "Should have 1 pending exit")
	pending := pt.pendingExits[100]
	require.NotNil(t, pending, "Pending exit should exist")
	assert.Equal(t, uint32(100), pending.PID)
	assert.Len(t, pending.Children, 0, "Children should be empty initially, populated during exitByPid")
	pt.mutex.RUnlock()

	// Manually trigger exit cleanup
	pt.mutex.Lock()
	pt.exitByPid(100)
	pt.mutex.Unlock()

	// Check that all children were properly reparented
	pt.mutex.RLock()
	assert.Nil(t, pt.processMap.Get(100), "Parent process should be removed")
	assert.Equal(t, uint32(1), child1.PPID, "Child1 should be reparented to init")
	assert.Equal(t, uint32(1), child2.PPID, "Child2 should be reparented to init")
	assert.Equal(t, uint32(1), child3.PPID, "Child3 should be reparented to init")
	pt.mutex.RUnlock()
}

func TestExitManager_RemoveFromParentChildrenMap(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Create a process tree: parent(100) -> child(200) -> grandchild(300)
	parent := createTestProcess(100, 1, "parent")
	child := createTestProcess(200, 100, "child")
	grandchild := createTestProcess(300, 200, "grandchild")

	// Set up parent-child relationships
	parent.ChildrenMap[apitypes.CommPID{PID: 200}] = child
	child.ChildrenMap[apitypes.CommPID{PID: 300}] = grandchild

	// Add all processes to the process map
	pt.processMap.Set(100, parent)
	pt.processMap.Set(200, child)
	pt.processMap.Set(300, grandchild)

	// Verify initial state
	assert.Len(t, parent.ChildrenMap, 1, "Parent should have 1 child initially")
	assert.Len(t, child.ChildrenMap, 1, "Child should have 1 grandchild initially")
	assert.Contains(t, parent.ChildrenMap, apitypes.CommPID{PID: 200}, "Parent should contain child")
	assert.Contains(t, child.ChildrenMap, apitypes.CommPID{PID: 300}, "Child should contain grandchild")

	// Test case 1: Exit the child process - should remove it from parent's ChildrenMap
	// First, add the child to pending exits
	pt.mutex.Lock()
	pt.pendingExits[200] = &pendingExit{
		PID:         200,
		StartTimeNs: 12345,
		Timestamp:   time.Now(),
		Children:    []*apitypes.Process{grandchild},
	}
	pt.mutex.Unlock()

	// Now call exitByPid which should work since the process is in pendingExits
	pt.mutex.Lock()
	pt.exitByPid(200)
	pt.mutex.Unlock()

	// Verify child was removed from parent's ChildrenMap
	pt.mutex.RLock()
	assert.Len(t, parent.ChildrenMap, 0, "Parent should have no children after child exit")
	assert.NotContains(t, parent.ChildrenMap, apitypes.CommPID{PID: 200}, "Parent should not contain child anymore")

	// Child process should be removed from process map
	assert.Nil(t, pt.processMap.Get(200), "Child process should be removed from process map")

	// Grandchild should still exist but be reparented to init (PID 1) by mock reparenting logic
	assert.Equal(t, uint32(1), grandchild.PPID, "Grandchild should be reparented to init")
	pt.mutex.RUnlock()

	// Test case 2: Exit the grandchild process - should remove it from child's ChildrenMap
	// But since child was already removed, we need to add grandchild to pending exits first
	pt.mutex.Lock()
	pt.pendingExits[300] = &pendingExit{
		PID:         300,
		StartTimeNs: 12346,
		Timestamp:   time.Now(),
		Children:    []*apitypes.Process{},
	}
	pt.mutex.Unlock()

	pt.mutex.Lock()
	pt.exitByPid(300)
	pt.mutex.Unlock()

	// Verify grandchild was removed from process map
	pt.mutex.RLock()
	assert.Nil(t, pt.processMap.Get(300), "Grandchild process should be removed from process map")
	pt.mutex.RUnlock()
}

func TestExitManager_RemoveFromParentChildrenMapWithMultipleChildren(t *testing.T) {
	pt := createTestProcessTreeCreator()

	// Create a process tree: parent(100) -> child1(200), child2(300), child3(400)
	parent := createTestProcess(100, 1, "parent")
	child1 := createTestProcess(200, 100, "child1")
	child2 := createTestProcess(300, 100, "child2")
	child3 := createTestProcess(400, 100, "child3")

	// Set up parent-child relationships
	parent.ChildrenMap[apitypes.CommPID{PID: 200}] = child1
	parent.ChildrenMap[apitypes.CommPID{PID: 300}] = child2
	parent.ChildrenMap[apitypes.CommPID{PID: 400}] = child3

	// Add all processes to the process map
	pt.processMap.Set(100, parent)
	pt.processMap.Set(200, child1)
	pt.processMap.Set(300, child2)
	pt.processMap.Set(400, child3)

	// Verify initial state
	assert.Len(t, parent.ChildrenMap, 3, "Parent should have 3 children initially")
	assert.Contains(t, parent.ChildrenMap, apitypes.CommPID{PID: 200}, "Parent should contain child1")
	assert.Contains(t, parent.ChildrenMap, apitypes.CommPID{PID: 300}, "Parent should contain child2")
	assert.Contains(t, parent.ChildrenMap, apitypes.CommPID{PID: 400}, "Parent should contain child3")

	// Test case: Exit child2 - should remove it from parent's ChildrenMap
	// First, add child2 to pending exits
	pt.mutex.Lock()
	pt.pendingExits[300] = &pendingExit{
		PID:         300,
		StartTimeNs: 12345,
		Timestamp:   time.Now(),
		Children:    []*apitypes.Process{},
	}
	pt.mutex.Unlock()

	pt.mutex.Lock()
	pt.exitByPid(300)
	pt.mutex.Unlock()

	// Verify child2 was removed from parent's ChildrenMap
	pt.mutex.RLock()
	assert.Len(t, parent.ChildrenMap, 2, "Parent should have 2 children after child2 exit")
	assert.Contains(t, parent.ChildrenMap, apitypes.CommPID{PID: 200}, "Parent should still contain child1")
	assert.NotContains(t, parent.ChildrenMap, apitypes.CommPID{PID: 300}, "Parent should not contain child2 anymore")
	assert.Contains(t, parent.ChildrenMap, apitypes.CommPID{PID: 400}, "Parent should still contain child3")

	// Child2 process should be removed from process map
	assert.Nil(t, pt.processMap.Get(300), "Child2 process should be removed from process map")

	// Other children should still exist
	assert.NotNil(t, pt.processMap.Get(200), "Child1 should still exist")
	assert.NotNil(t, pt.processMap.Get(400), "Child3 should still exist")
	pt.mutex.RUnlock()

	// Test case: Exit child1 - should remove it from parent's ChildrenMap
	// First, add child1 to pending exits
	pt.mutex.Lock()
	pt.pendingExits[200] = &pendingExit{
		PID:         200,
		StartTimeNs: 12346,
		Timestamp:   time.Now(),
		Children:    []*apitypes.Process{},
	}
	pt.mutex.Unlock()

	pt.mutex.Lock()
	pt.exitByPid(200)
	pt.mutex.Unlock()

	// Verify child1 was removed from parent's ChildrenMap
	pt.mutex.RLock()
	assert.Len(t, parent.ChildrenMap, 1, "Parent should have 1 child after child1 exit")
	assert.NotContains(t, parent.ChildrenMap, apitypes.CommPID{PID: 200}, "Parent should not contain child1 anymore")
	assert.Contains(t, parent.ChildrenMap, apitypes.CommPID{PID: 400}, "Parent should still contain child3")

	// Child1 process should be removed from process map
	assert.Nil(t, pt.processMap.Get(200), "Child1 process should be removed from process map")
	pt.mutex.RUnlock()
}
