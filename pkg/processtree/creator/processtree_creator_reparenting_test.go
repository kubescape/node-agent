package processtreecreator

import (
	"fmt"
	"sync"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessTreeCreator_HandleExitEvent_WithReparenting(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)
	require.NotNil(t, creator.reparentingLogic, "Reparenting logic should be initialized")

	// Create a process tree with a parent and children
	parentPID := uint32(100)
	child1PID := uint32(200)
	child2PID := uint32(201)

	// Create parent process
	parent := &apitypes.Process{
		PID:         parentPID,
		PPID:        1,
		Comm:        "parent-process",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	// Create child processes
	child1 := &apitypes.Process{
		PID:         child1PID,
		PPID:        parentPID,
		Comm:        "child1",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	child2 := &apitypes.Process{
		PID:         child2PID,
		PPID:        parentPID,
		Comm:        "child2",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	// Add children to parent
	parent.ChildrenMap[apitypes.CommPID{Comm: child1.Comm, PID: child1.PID}] = child1
	parent.ChildrenMap[apitypes.CommPID{Comm: child2.Comm, PID: child2.PID}] = child2

	// Add processes to the creator's process map
	creator.processMap[parentPID] = parent
	creator.processMap[child1PID] = child1
	creator.processMap[child2PID] = child2

	// Create exit event for parent
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         parentPID,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}

	// Handle the exit event
	creator.handleExitEvent(exitEvent)

	// Verify that parent was removed
	assert.Nil(t, creator.processMap[parentPID], "Parent process should be removed")

	// Verify that children still exist but have new PPID
	assert.NotNil(t, creator.processMap[child1PID], "Child1 should still exist")
	assert.NotNil(t, creator.processMap[child2PID], "Child2 should still exist")

	// Verify that children have new PPID (should be 1 for default strategy)
	assert.Equal(t, uint32(1), creator.processMap[child1PID].PPID, "Child1 should be reparented to init")
	assert.Equal(t, uint32(1), creator.processMap[child2PID].PPID, "Child2 should be reparented to init")
}

func TestProcessTreeCreator_HandleExitEvent_ContainerdScenario(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)
	require.NotNil(t, creator.reparentingLogic)

	// Create a mock container tree that simulates containerd behavior
	mockContainerTree := &MockContainerTree{
		shimPID: 50,
		containerProcesses: map[uint32]bool{
			100: true, // parent is under container
			200: true, // child1 is under container
			201: true, // child2 is under container
		},
	}

	creator.containerTree = mockContainerTree

	// Create a process tree with a container process and children
	parentPID := uint32(100)
	child1PID := uint32(200)
	child2PID := uint32(201)

	// Create parent process (container process)
	parent := &apitypes.Process{
		PID:         parentPID,
		PPID:        50, // shim PID
		Comm:        "nginx",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	// Create child processes
	child1 := &apitypes.Process{
		PID:         child1PID,
		PPID:        parentPID,
		Comm:        "nginx-worker",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	child2 := &apitypes.Process{
		PID:         child2PID,
		PPID:        parentPID,
		Comm:        "nginx-cache",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	// Add children to parent
	parent.ChildrenMap[apitypes.CommPID{Comm: child1.Comm, PID: child1.PID}] = child1
	parent.ChildrenMap[apitypes.CommPID{Comm: child2.Comm, PID: child2.PID}] = child2

	// Add processes to the creator's process map
	creator.processMap[parentPID] = parent
	creator.processMap[child1PID] = child1
	creator.processMap[child2PID] = child2
	creator.processMap[50] = &apitypes.Process{ // shim process
		PID:         50,
		PPID:        1,
		Comm:        "containerd-shim",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	// Create exit event for parent
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         parentPID,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}

	// Handle the exit event
	creator.handleExitEvent(exitEvent)

	// Verify that parent was removed
	assert.Nil(t, creator.processMap[parentPID], "Parent process should be removed")

	// Verify that children still exist but have new PPID (should be shim PID for containerd strategy)
	assert.NotNil(t, creator.processMap[child1PID], "Child1 should still exist")
	assert.NotNil(t, creator.processMap[child2PID], "Child2 should still exist")

	// Verify that children have new PPID (should be shim PID for containerd strategy)
	assert.Equal(t, uint32(50), creator.processMap[child1PID].PPID, "Child1 should be reparented to shim")
	assert.Equal(t, uint32(50), creator.processMap[child2PID].PPID, "Child2 should be reparented to shim")
}

func TestProcessTreeCreator_HandleExitEvent_NoChildren(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)

	// Create a process without children
	parentPID := uint32(100)
	parent := &apitypes.Process{
		PID:         parentPID,
		PPID:        1,
		Comm:        "parent-process",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	creator.processMap[parentPID] = parent

	// Create exit event
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         parentPID,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}

	// Handle the exit event
	creator.handleExitEvent(exitEvent)

	// Verify that parent was removed
	assert.Nil(t, creator.processMap[parentPID], "Parent process should be removed")
}

func TestProcessTreeCreator_HandleExitEvent_ProcessNotExists(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)

	// Create exit event for non-existent process
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         999,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}

	// Handle the exit event - should not panic or error
	creator.handleExitEvent(exitEvent)

	// Verify that nothing was changed
	assert.Len(t, creator.processMap, 0, "Process map should remain empty")
}

func TestProcessTreeCreator_Reparenting_EdgeCases(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)

	// Edge 1: Child already has a parent
	parent1 := &apitypes.Process{PID: 10, Comm: "parent1", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	parent2 := &apitypes.Process{PID: 20, Comm: "parent2", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	child := &apitypes.Process{PID: 30, PPID: 10, Comm: "child", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	parent1.ChildrenMap[apitypes.CommPID{Comm: child.Comm, PID: child.PID}] = child
	creator.processMap[10] = parent1
	creator.processMap[20] = parent2
	creator.processMap[30] = child

	// Reparent child from parent1 to parent2
	child.PPID = 20
	creator.linkProcessToParent(child)
	// Should be added to parent2 (linkProcessToParent only adds, doesn't remove from old parent)
	_, inOld := parent1.ChildrenMap[apitypes.CommPID{Comm: child.Comm, PID: child.PID}]
	_, inNew := parent2.ChildrenMap[apitypes.CommPID{Comm: child.Comm, PID: child.PID}]
	assert.True(t, inOld, "Child should remain in old parent (linkProcessToParent only adds)")
	assert.True(t, inNew, "Child should be added to new parent")

	// Edge 2: New parent does not exist
	child.PPID = 99 // No such parent
	creator.linkProcessToParent(child)
	_, exists := creator.processMap[99]
	assert.True(t, exists, "Missing parent should be created")

	// Edge 3: Child is nil
	creator.linkProcessToParent(nil) // Should not panic

	// Edge 4: Parent is its own child (cycle)
	cycle := &apitypes.Process{PID: 42, PPID: 42, Comm: "cycle", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	creator.processMap[42] = cycle
	creator.linkProcessToParent(cycle) // Should not panic or infinite loop
	_, inSelf := cycle.ChildrenMap[apitypes.CommPID{Comm: cycle.Comm, PID: cycle.PID}]
	assert.True(t, inSelf, "Process can be its own child (cycle)")

	// Edge 5: Child already in new parent's ChildrenMap
	parent3 := &apitypes.Process{PID: 50, Comm: "parent3", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	child2 := &apitypes.Process{PID: 60, PPID: 50, Comm: "child2", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	parent3.ChildrenMap[apitypes.CommPID{Comm: child2.Comm, PID: child2.PID}] = child2
	creator.processMap[50] = parent3
	creator.processMap[60] = child2
	// Re-link, should not duplicate or error
	creator.linkProcessToParent(child2)
	count := 0
	for k := range parent3.ChildrenMap {
		if k == (apitypes.CommPID{Comm: child2.Comm, PID: child2.PID}) {
			count++
		}
	}
	assert.Equal(t, 1, count, "Child should not be duplicated in ChildrenMap")
}

// MockContainerTree is a mock implementation for testing
type MockContainerTree struct {
	shimPID            uint32
	containerProcesses map[uint32]bool
}

func (mct *MockContainerTree) ContainerCallback(notif containercollection.PubSubEvent) {}
func (mct *MockContainerTree) GetContainerTreeNodes(containerID string, fullTree map[uint32]*apitypes.Process) ([]apitypes.Process, error) {
	return nil, nil
}
func (mct *MockContainerTree) GetContainerSubtree(containerID string, targetPID uint32, fullTree map[uint32]*apitypes.Process) (apitypes.Process, error) {
	return apitypes.Process{}, nil
}
func (mct *MockContainerTree) ListContainers() []string {
	return nil
}
func (mct *MockContainerTree) IsProcessUnderAnyContainerSubtree(pid uint32, fullTree map[uint32]*apitypes.Process) bool {
	return mct.containerProcesses[pid]
}
func (mct *MockContainerTree) GetShimPIDForProcess(pid uint32, fullTree map[uint32]*apitypes.Process) (uint32, bool) {
	if mct.containerProcesses[pid] {
		return mct.shimPID, true
	}
	return 0, false
}
func (mct *MockContainerTree) IsPPIDUnderAnyContainerSubtree(ppid uint32, fullTree map[uint32]*apitypes.Process) bool {
	return mct.containerProcesses[ppid]
}
func (mct *MockContainerTree) SetShimPIDForTesting(containerID string, shimPID uint32) {}

func TestProcessTreeCreator_ExitEvent_ComplexScenarios(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)

	// Test 1: Multiple levels of reparenting
	// Create a deep tree: root -> parent -> child -> grandchild
	root := &apitypes.Process{PID: 1, Comm: "root", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	parent := &apitypes.Process{PID: 10, PPID: 1, Comm: "parent", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	child := &apitypes.Process{PID: 100, PPID: 10, Comm: "child", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	grandchild := &apitypes.Process{PID: 1000, PPID: 100, Comm: "grandchild", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}

	// Build the tree
	root.ChildrenMap[apitypes.CommPID{Comm: parent.Comm, PID: parent.PID}] = parent
	parent.ChildrenMap[apitypes.CommPID{Comm: child.Comm, PID: child.PID}] = child
	child.ChildrenMap[apitypes.CommPID{Comm: grandchild.Comm, PID: grandchild.PID}] = grandchild

	creator.processMap[1] = root
	creator.processMap[10] = parent
	creator.processMap[100] = child
	creator.processMap[1000] = grandchild

	// Exit the parent - child and grandchild should be reparented to root
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         10,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}

	creator.handleExitEvent(exitEvent)

	// Verify parent is removed
	assert.Nil(t, creator.processMap[10], "Parent should be removed")

	// Verify child and grandchild are reparented to root
	assert.Equal(t, uint32(1), creator.processMap[100].PPID, "Child should be reparented to root")
	assert.Equal(t, uint32(100), creator.processMap[1000].PPID, "Grandchild should keep its parent")

	// Verify root has both child and grandchild in its subtree
	rootAfter := creator.processMap[1]
	assert.Contains(t, rootAfter.ChildrenMap, apitypes.CommPID{Comm: "child", PID: 100}, "Root should have child")
}

func TestProcessTreeCreator_ExitEvent_RepeatedExits(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)

	// Test handling multiple exit events for the same process
	process := &apitypes.Process{PID: 100, Comm: "test", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	creator.processMap[100] = process

	// First exit event
	exitEvent1 := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         100,
		StartTimeNs: 1000,
	}
	creator.handleExitEvent(exitEvent1)

	// Process should be removed
	assert.Nil(t, creator.processMap[100], "Process should be removed after first exit")

	// Second exit event for same PID (should be ignored)
	exitEvent2 := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         100,
		StartTimeNs: 2000,
	}
	creator.handleExitEvent(exitEvent2)

	// Process should still be nil
	assert.Nil(t, creator.processMap[100], "Process should remain removed after second exit")
}

func TestProcessTreeCreator_ExitEvent_WithReusedPID(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)

	// Test PID reuse scenario
	process1 := &apitypes.Process{PID: 100, Comm: "process1", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	creator.processMap[100] = process1

	// Exit first process
	exitEvent1 := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         100,
		StartTimeNs: 1000,
	}
	creator.handleExitEvent(exitEvent1)

	// Process should be removed
	assert.Nil(t, creator.processMap[100], "First process should be removed")

	// Create new process with same PID but different start time
	process2 := &apitypes.Process{PID: 100, Comm: "process2", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	creator.processMap[100] = process2

	// Try to exit with old start time (current implementation will exit the new process because it only checks PID)
	exitEvent2 := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         100,
		StartTimeNs: 1000, // Old start time
	}
	creator.handleExitEvent(exitEvent2)

	// Current behavior: new process will be removed because handleExitEvent only checks PID, not start time
	assert.Nil(t, creator.processMap[100], "New process is removed because handleExitEvent only checks PID")

	// Create another new process
	process3 := &apitypes.Process{PID: 100, Comm: "process3", ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process)}
	creator.processMap[100] = process3

	// Exit with correct start time (should work)
	exitEvent3 := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         100,
		StartTimeNs: 2000, // New start time - different from the old one
	}
	creator.handleExitEvent(exitEvent3)

	// Process should be removed
	assert.Nil(t, creator.processMap[100], "New process should be removed with correct start time")
}

func TestProcessTreeCreator_ExitEvent_ReparentingStrategies(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)

	// Test different reparenting strategies
	tests := []struct {
		name           string
		parentComm     string
		expectedParent uint32
	}{
		{"systemd_parent", "systemd", 1},            // systemd strategy should reparent to init
		{"docker_parent", "docker", 1},              // docker strategy should reparent to init
		{"containerd_parent", "containerd-shim", 1}, // containerd strategy should reparent to init
		{"regular_parent", "nginx", 1},              // default strategy should reparent to init
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create parent and child
			parent := &apitypes.Process{
				PID:         100,
				PPID:        1,
				Comm:        tt.parentComm,
				ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
			}
			child := &apitypes.Process{
				PID:         200,
				PPID:        100,
				Comm:        "child",
				ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
			}

			parent.ChildrenMap[apitypes.CommPID{Comm: child.Comm, PID: child.PID}] = child
			creator.processMap[100] = parent
			creator.processMap[200] = child

			// Exit parent
			exitEvent := feeder.ProcessEvent{
				Type:        feeder.ExitEvent,
				PID:         100,
				StartTimeNs: uint64(time.Now().UnixNano()),
			}
			creator.handleExitEvent(exitEvent)

			// Verify child is reparented correctly
			assert.Nil(t, creator.processMap[100], "Parent should be removed")
			assert.Equal(t, tt.expectedParent, creator.processMap[200].PPID,
				fmt.Sprintf("Child should be reparented to %d for %s", tt.expectedParent, tt.name))

			// Clean up for next test
			delete(creator.processMap, 200)
		})
	}
}

func TestProcessTreeCreator_ExitEvent_ConcurrentExits(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)

	// Test concurrent exit events
	var wg sync.WaitGroup
	numProcesses := 10

	// Create multiple processes
	for i := 0; i < numProcesses; i++ {
		pid := uint32(1000 + i)
		process := &apitypes.Process{
			PID:         pid,
			Comm:        fmt.Sprintf("process%d", i),
			ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
		}
		creator.processMap[pid] = process
	}

	// Exit all processes concurrently
	for i := 0; i < numProcesses; i++ {
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()
			exitEvent := feeder.ProcessEvent{
				Type:        feeder.ExitEvent,
				PID:         pid,
				StartTimeNs: uint64(time.Now().UnixNano()),
			}
			creator.handleExitEvent(exitEvent)
		}(uint32(1000 + i))
	}

	wg.Wait()

	// Verify all processes are removed
	for i := 0; i < numProcesses; i++ {
		pid := uint32(1000 + i)
		assert.Nil(t, creator.processMap[pid], fmt.Sprintf("Process %d should be removed", pid))
	}
}

func TestProcessTreeCreator_ExitEvent_WithContainerTree(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)

	// Mock container tree
	mockContainerTree := &MockContainerTree{
		shimPID: 50,
		containerProcesses: map[uint32]bool{
			100: true, // container process
			200: true, // container child
		},
	}
	creator.containerTree = mockContainerTree

	// Create container process and child
	container := &apitypes.Process{
		PID:         100,
		PPID:        50, // shim
		Comm:        "nginx",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	child := &apitypes.Process{
		PID:         200,
		PPID:        100,
		Comm:        "nginx-worker",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	container.ChildrenMap[apitypes.CommPID{Comm: child.Comm, PID: child.PID}] = child
	creator.processMap[100] = container
	creator.processMap[200] = child
	creator.processMap[50] = &apitypes.Process{ // shim process
		PID:         50,
		PPID:        1,
		Comm:        "containerd-shim",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	// Exit container process
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         100,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}
	creator.handleExitEvent(exitEvent)

	// Verify container is removed
	assert.Nil(t, creator.processMap[100], "Container process should be removed")

	// Verify child is reparented to shim (containerd strategy)
	assert.Equal(t, uint32(50), creator.processMap[200].PPID, "Child should be reparented to shim")
}

func TestProcessTreeCreator_ExitEvent_EdgeCases(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)

	// Test 1: Exit process with nil ChildrenMap
	process1 := &apitypes.Process{PID: 100, Comm: "process1"} // nil ChildrenMap
	creator.processMap[100] = process1

	exitEvent1 := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         100,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}
	creator.handleExitEvent(exitEvent1) // Should not panic

	// Test 2: Exit process with empty ChildrenMap
	process2 := &apitypes.Process{
		PID:         200,
		Comm:        "process2",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	creator.processMap[200] = process2

	exitEvent2 := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         200,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}
	creator.handleExitEvent(exitEvent2) // Should not panic

	// Test 3: Exit process with nil child in ChildrenMap
	process3 := &apitypes.Process{
		PID:         300,
		Comm:        "process3",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	process3.ChildrenMap[apitypes.CommPID{Comm: "nil-child", PID: 999}] = nil
	creator.processMap[300] = process3

	exitEvent3 := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         300,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}
	creator.handleExitEvent(exitEvent3) // Should not panic

	// Verify all processes are removed
	assert.Nil(t, creator.processMap[100], "Process1 should be removed")
	assert.Nil(t, creator.processMap[200], "Process2 should be removed")
	assert.Nil(t, creator.processMap[300], "Process3 should be removed")
}

func TestProcessTreeCreator_ExitEvent_ReparentingVerification(t *testing.T) {
	creator := NewProcessTreeCreator().(*processTreeCreatorImpl)

	// Test that reparenting verification works correctly
	parent := &apitypes.Process{
		PID:         100,
		PPID:        1,
		Comm:        "parent",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
	child := &apitypes.Process{
		PID:         200,
		PPID:        100,
		Comm:        "child",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	parent.ChildrenMap[apitypes.CommPID{Comm: child.Comm, PID: child.PID}] = child
	creator.processMap[100] = parent
	creator.processMap[200] = child

	// Exit parent
	exitEvent := feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         100,
		StartTimeNs: uint64(time.Now().UnixNano()),
	}
	creator.handleExitEvent(exitEvent)

	// Verify reparenting result
	assert.Nil(t, creator.processMap[100], "Parent should be removed")
	assert.NotNil(t, creator.processMap[200], "Child should still exist")
	assert.Equal(t, uint32(1), creator.processMap[200].PPID, "Child should be reparented to init")

	// Verify child is properly linked to new parent
	initProcess := creator.processMap[1]
	if initProcess == nil {
		// Init process might not exist, create it
		initProcess = &apitypes.Process{
			PID:         1,
			Comm:        "init",
			ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
		}
		creator.processMap[1] = initProcess
	}
	assert.Contains(t, initProcess.ChildrenMap, apitypes.CommPID{Comm: "child", PID: 200},
		"Child should be in init's ChildrenMap")
}
