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
type mockContainerProcessTree struct {
	channel chan uint32
}

func newMockContainerProcessTree(channel chan uint32) *mockContainerProcessTree {
	return &mockContainerProcessTree{
		channel: channel,
	}
}

func (m *mockContainerProcessTree) ContainerCallback(notif containercollection.PubSubEvent) {}

// TriggerContainerExit simulates a container exit by sending a PID to the exit channel
func (m *mockContainerProcessTree) TriggerContainerExit(pid uint32) {
	select {
	case m.channel <- pid:
	default:
		// Channel might be full or not being read, just skip
	}
}

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

	exitChan := make(chan uint32, 10)
	return &processTreeCreatorImpl{
		processMap:            maps.SafeMap[uint32, *apitypes.Process]{},
		containerTree:         newMockContainerProcessTree(exitChan),
		reparentingStrategies: &mockReparentingLogic{},
		pendingExits:          make(map[uint32]*pendingExit),
		config:                testConfig,
		containerExitChan:     exitChan,
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
	parent.ChildrenMap[apitypes.CommPID{Comm: "child", PID: 200}] = child

	pt.processMap.Set(100, parent)
	pt.processMap.Set(200, child)

	// Test adding a pending exit
	pt.mutex.Lock()
	event := createTestExitEvent(100, 12345)
	children := []*apitypes.Process{child}
	pt.addPendingExit(event, children)
	pt.mutex.Unlock()

	// Check that the exit was added
	pt.mutex.RLock()
	require.Equal(t, 1, len(pt.pendingExits), "Should have 1 pending exit")
	pending := pt.pendingExits[100]
	require.NotNil(t, pending, "Pending exit should exist")
	assert.Equal(t, uint32(100), pending.PID)
	assert.Equal(t, uint64(12345), pending.StartTimeNs)
	assert.Len(t, pending.Children, 1)
	assert.Equal(t, uint32(200), pending.Children[0].PID)
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

	parent.ChildrenMap[apitypes.CommPID{Comm: "child1", PID: 200}] = child1
	parent.ChildrenMap[apitypes.CommPID{Comm: "child2", PID: 300}] = child2

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
			pt.addPendingExit(event, []*apitypes.Process{})
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

	parent.ChildrenMap[apitypes.CommPID{Comm: "child1", PID: 200}] = child1
	parent.ChildrenMap[apitypes.CommPID{Comm: "child2", PID: 300}] = child2

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
	assert.Len(t, pending.Children, 2, "Should have 2 children")

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
	grandparent.ChildrenMap[apitypes.CommPID{Comm: "parent", PID: 100}] = parent
	parent.ChildrenMap[apitypes.CommPID{Comm: "child1", PID: 200}] = child1
	parent.ChildrenMap[apitypes.CommPID{Comm: "child2", PID: 300}] = child2
	child2.ChildrenMap[apitypes.CommPID{Comm: "grandchild", PID: 400}] = grandchild

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

func TestDeleteAllTreeUnderPid(t *testing.T) {
	// Create process tree creator
	containerTree := &mockContainerProcessTree{}
	exitChan := make(chan uint32, 10)
	cfg := config.Config{
		ExitCleanup: processtreecreatorconfig.ExitCleanupConfig{
			MaxPendingExits: 1000,
			CleanupDelay:    5 * time.Minute,
			CleanupInterval: 30 * time.Second,
		},
	}

	pt := NewProcessTreeCreator(containerTree, cfg, exitChan).(*processTreeCreatorImpl)

	// Create a process tree structure:
	// Root (PID 1)
	//   ├── Parent (PID 100)
	//       ├── Child1 (PID 200)
	//       │   └── Grandchild1 (PID 300)
	//       └── Child2 (PID 201)
	//           └── Grandchild2 (PID 301)

	// Create root process
	root := &apitypes.Process{
		PID:         1,
		PPID:        0,
		Comm:        "init",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	pt.processMap.Set(1, root)

	// Create parent process
	parent := &apitypes.Process{
		PID:         100,
		PPID:        1,
		Comm:        "parent",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	pt.processMap.Set(100, parent)
	root.ChildrenMap[apitypes.CommPID{Comm: "parent", PID: 100}] = parent

	// Create child1
	child1 := &apitypes.Process{
		PID:         200,
		PPID:        100,
		Comm:        "child1",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	pt.processMap.Set(200, child1)
	parent.ChildrenMap[apitypes.CommPID{Comm: "child1", PID: 200}] = child1

	// Create grandchild1
	grandchild1 := &apitypes.Process{
		PID:         300,
		PPID:        200,
		Comm:        "grandchild1",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	pt.processMap.Set(300, grandchild1)
	child1.ChildrenMap[apitypes.CommPID{Comm: "grandchild1", PID: 300}] = grandchild1

	// Create child2
	child2 := &apitypes.Process{
		PID:         201,
		PPID:        100,
		Comm:        "child2",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	pt.processMap.Set(201, child2)
	parent.ChildrenMap[apitypes.CommPID{Comm: "child2", PID: 201}] = child2

	// Create grandchild2
	grandchild2 := &apitypes.Process{
		PID:         301,
		PPID:        201,
		Comm:        "grandchild2",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	pt.processMap.Set(301, grandchild2)
	child2.ChildrenMap[apitypes.CommPID{Comm: "grandchild2", PID: 301}] = grandchild2

	// Add some pending exits
	pt.pendingExits[100] = &pendingExit{PID: 100, StartTimeNs: 1000, Timestamp: time.Now()}
	pt.pendingExits[200] = &pendingExit{PID: 200, StartTimeNs: 2000, Timestamp: time.Now()}
	pt.pendingExits[300] = &pendingExit{PID: 300, StartTimeNs: 3000, Timestamp: time.Now()}

	// Verify initial state
	assert.NotNil(t, pt.processMap.Get(1), "Root should exist")
	assert.NotNil(t, pt.processMap.Get(100), "Parent should exist")
	assert.NotNil(t, pt.processMap.Get(200), "Child1 should exist")
	assert.NotNil(t, pt.processMap.Get(201), "Child2 should exist")
	assert.NotNil(t, pt.processMap.Get(300), "Grandchild1 should exist")
	assert.NotNil(t, pt.processMap.Get(301), "Grandchild2 should exist")
	assert.Len(t, root.ChildrenMap, 1, "Root should have 1 child")
	assert.Len(t, parent.ChildrenMap, 2, "Parent should have 2 children")
	assert.Len(t, pt.pendingExits, 3, "Should have 3 pending exits")

	// Delete the entire subtree under parent (PID 100)
	pt.deleteAllTreeUnderPid(100)

	// Verify that all processes in the subtree are deleted
	assert.NotNil(t, pt.processMap.Get(1), "Root should still exist")
	assert.Nil(t, pt.processMap.Get(100), "Parent should be deleted")
	assert.Nil(t, pt.processMap.Get(200), "Child1 should be deleted")
	assert.Nil(t, pt.processMap.Get(201), "Child2 should be deleted")
	assert.Nil(t, pt.processMap.Get(300), "Grandchild1 should be deleted")
	assert.Nil(t, pt.processMap.Get(301), "Grandchild2 should be deleted")

	// Verify that root's children map is updated
	assert.Len(t, root.ChildrenMap, 0, "Root should have no children after deletion")

	// Verify that pending exits are cleaned up
	assert.Len(t, pt.pendingExits, 0, "All pending exits should be cleaned up")
}

func TestDeleteAllTreeUnderPid_NonExistentProcess(t *testing.T) {
	// Create process tree creator
	containerTree := &mockContainerProcessTree{}
	exitChan := make(chan uint32, 10)
	cfg := config.Config{
		ExitCleanup: processtreecreatorconfig.ExitCleanupConfig{
			MaxPendingExits: 1000,
			CleanupDelay:    5 * time.Minute,
			CleanupInterval: 30 * time.Second,
		},
	}

	pt := NewProcessTreeCreator(containerTree, cfg, exitChan).(*processTreeCreatorImpl)

	// Try to delete a non-existent process
	pt.deleteAllTreeUnderPid(999)

	// Should not panic or cause any issues
	assert.Equal(t, 0, pt.processMap.Len(), "Process map should be empty")
}

func TestContainerExitFlow(t *testing.T) {
	// Create process tree creator
	exitChan := make(chan uint32, 10)
	containerTree := newMockContainerProcessTree(exitChan)
	cfg := config.Config{
		ExitCleanup: processtreecreatorconfig.ExitCleanupConfig{
			MaxPendingExits: 1000,
			CleanupDelay:    5 * time.Minute,
			CleanupInterval: 30 * time.Second,
		},
	}

	pt := NewProcessTreeCreator(containerTree, cfg, exitChan).(*processTreeCreatorImpl)

	// Create a process tree structure:
	// Shim (PID 100) - this is the container shim
	//   ├── Container Process (PID 200)
	//       └── App Process (PID 300)

	// Create shim process
	shim := &apitypes.Process{
		PID:         100,
		PPID:        1,
		Comm:        "containerd-shim",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	pt.processMap.Set(100, shim)

	// Create container process
	containerProc := &apitypes.Process{
		PID:         200,
		PPID:        100,
		Comm:        "container-main",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	pt.processMap.Set(200, containerProc)
	shim.ChildrenMap[apitypes.CommPID{Comm: "container-main", PID: 200}] = containerProc

	// Create app process
	app := &apitypes.Process{
		PID:         300,
		PPID:        200,
		Comm:        "app",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	pt.processMap.Set(300, app)
	containerProc.ChildrenMap[apitypes.CommPID{Comm: "app", PID: 300}] = app

	// Verify initial state
	assert.NotNil(t, pt.processMap.Get(100), "Shim should exist")
	assert.NotNil(t, pt.processMap.Get(200), "Container process should exist")
	assert.NotNil(t, pt.processMap.Get(300), "App process should exist")
	assert.Len(t, shim.ChildrenMap, 1, "Shim should have 1 child")
	assert.Len(t, containerProc.ChildrenMap, 1, "Container process should have 1 child")

	// Start the exit manager to handle channel events
	pt.startExitManager()
	defer pt.stopExitManager()

	// Simulate container exit by triggering the mock
	containerTree.TriggerContainerExit(100) // Send shim PID

	// Give some time for the goroutine to process the channel event
	time.Sleep(100 * time.Millisecond)

	// Verify that the entire tree under the shim is deleted
	assert.Nil(t, pt.processMap.Get(100), "Shim should be deleted")
	assert.Nil(t, pt.processMap.Get(200), "Container process should be deleted")
	assert.Nil(t, pt.processMap.Get(300), "App process should be deleted")
}

func TestExitByPidWithChannelFlow(t *testing.T) {
	// Create process tree creator
	exitChan := make(chan uint32, 10)
	containerTree := newMockContainerProcessTree(exitChan)
	cfg := config.Config{
		ExitCleanup: processtreecreatorconfig.ExitCleanupConfig{
			MaxPendingExits: 1000,
			CleanupDelay:    5 * time.Minute,
			CleanupInterval: 30 * time.Second,
		},
	}

	pt := NewProcessTreeCreator(containerTree, cfg, exitChan).(*processTreeCreatorImpl)

	// Create a simple process
	proc := &apitypes.Process{
		PID:         100,
		PPID:        1,
		Comm:        "test-process",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	pt.processMap.Set(100, proc)

	// Verify initial state
	assert.NotNil(t, pt.processMap.Get(100), "Process should exist initially")

	// Start the exit manager to handle channel events
	pt.startExitManager()
	defer pt.stopExitManager()

	// Send PID to channel
	exitChan <- 100

	// Give some time for the goroutine to process the channel event
	time.Sleep(100 * time.Millisecond)

	// Verify that the process was deleted
	assert.Nil(t, pt.processMap.Get(100), "Process should be deleted after channel processing")
}

func TestExitByPidWithChannelStopSignal(t *testing.T) {
	// Create process tree creator
	exitChan := make(chan uint32, 10)
	containerTree := newMockContainerProcessTree(exitChan)
	cfg := config.Config{
		ExitCleanup: processtreecreatorconfig.ExitCleanupConfig{
			MaxPendingExits: 1000,
			CleanupDelay:    5 * time.Minute,
			CleanupInterval: 30 * time.Second,
		},
	}

	pt := NewProcessTreeCreator(containerTree, cfg, exitChan).(*processTreeCreatorImpl)
	pt.exitCleanupStopChan = make(chan struct{})

	// Test that exitByPidWithChannel returns when stop signal is sent
	stopped := make(chan bool, 1)
	go func() {
		pt.exitByPidWithChannel()
		stopped <- true
	}()

	// Send stop signal
	close(pt.exitCleanupStopChan)

	// Verify that the function returned
	select {
	case <-stopped:
		// Good, function returned
	case <-time.After(100 * time.Millisecond):
		t.Fatal("exitByPidWithChannel should have returned after stop signal")
	}
}
