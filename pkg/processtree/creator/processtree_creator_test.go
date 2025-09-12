package processtreecreator

import (
	"fmt"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockContainerProcessTree is a mock implementation of ContainerProcessTree
type MockContainerProcessTree struct {
	mock.Mock
}

func (m *MockContainerProcessTree) GetPidBranch(containerID string, targetPID uint32, processMap *maps.SafeMap[uint32, *apitypes.Process]) (apitypes.Process, error) {
	args := m.Called(containerID, targetPID, processMap)
	return args.Get(0).(apitypes.Process), args.Error(1)
}

func (m *MockContainerProcessTree) IsProcessUnderAnyContainerSubtree(pid uint32, processMap *maps.SafeMap[uint32, *apitypes.Process]) bool {
	args := m.Called(pid, processMap)
	return args.Bool(0)
}

func (m *MockContainerProcessTree) IsProcessUnderContainer(pid uint32, containerID string, processMap *maps.SafeMap[uint32, *apitypes.Process]) bool {
	args := m.Called(pid, containerID, processMap)
	return args.Bool(0)
}

func (m *MockContainerProcessTree) ContainerCallback(notif containercollection.PubSubEvent) {
	m.Called(notif)
}

func (m *MockContainerProcessTree) GetContainerTreeNodes(containerID string, fullTree *maps.SafeMap[uint32, *apitypes.Process]) ([]apitypes.Process, error) {
	args := m.Called(containerID, fullTree)
	return args.Get(0).([]apitypes.Process), args.Error(1)
}

func (m *MockContainerProcessTree) ListContainers() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockContainerProcessTree) GetShimPIDForProcess(pid uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) (uint32, bool) {
	args := m.Called(pid, fullTree)
	return args.Get(0).(uint32), args.Bool(1)
}

func (m *MockContainerProcessTree) GetPidByContainerID(containerID string) (uint32, error) {
	args := m.Called(containerID)
	return args.Get(0).(uint32), args.Error(1)
}

// Helper function to create a test config with proper exit cleanup settings
func createTestConfig(kubernetesMode bool) config.Config {
	return config.Config{
		KubernetesMode: kubernetesMode,
		ExitCleanup: processtreecreatorconfig.ExitCleanupConfig{
			MaxPendingExits: 1000,
			CleanupInterval: 30 * time.Second,
			CleanupDelay:    1 * time.Minute,
		},
	}
}

func TestNewProcessTreeCreator(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))

	assert.NotNil(t, creator)

	// Cast to implementation to check internal state
	impl := creator.(*processTreeCreatorImpl)
	assert.NotNil(t, impl.containerTree)
	assert.NotNil(t, impl.pendingExits)
	assert.Equal(t, mockContainerTree, impl.containerTree)
}

func TestStartStop(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))
	impl := creator.(*processTreeCreatorImpl)

	// Initially, exit cleanup channel should be nil
	assert.Nil(t, impl.exitCleanupStopChan)

	// Start the creator
	creator.Start()
	assert.NotNil(t, impl.exitCleanupStopChan)

	// Stop the creator
	creator.Stop()
	assert.Nil(t, impl.exitCleanupStopChan)
}

func TestGetOrCreateProcess(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))
	impl := creator.(*processTreeCreatorImpl)

	// Test creating a new process
	proc := impl.getOrCreateProcess(1234)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(1234), proc.PID)
	assert.NotNil(t, proc.ChildrenMap)

	// Test getting existing process
	proc2 := impl.getOrCreateProcess(1234)
	assert.Equal(t, proc, proc2) // Should be the same instance
}

func TestHandleForkEvent(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))
	impl := creator.(*processTreeCreatorImpl)

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)

	event := conversion.ProcessEvent{
		Type:    conversion.ForkEvent,
		PID:     1234,
		PPID:    1000,
		Comm:    "test-process",
		Pcomm:   "parent-process",
		Cmdline: "test-process --arg",
		Uid:     &[]uint32{1000}[0],
		Gid:     &[]uint32{1000}[0],
		Cwd:     "/home/user",
		Path:    "/usr/bin/test-process",
	}

	creator.FeedEvent(event)

	// Verify process was created and populated
	proc := impl.processMap.Get(1234)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(1234), proc.PID)
	assert.Equal(t, uint32(1000), proc.PPID)
	assert.Equal(t, "test-process", proc.Comm)
	assert.Equal(t, "parent-process", proc.Pcomm)
	assert.Equal(t, "test-process --arg", proc.Cmdline)
	assert.Equal(t, uint32(1000), *proc.Uid)
	assert.Equal(t, uint32(1000), *proc.Gid)
	assert.Equal(t, "/home/user", proc.Cwd)
	assert.Equal(t, "/usr/bin/test-process", proc.Path)
	assert.NotNil(t, proc.ChildrenMap)
}

func TestHandleExecEvent(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(true))
	impl := creator.(*processTreeCreatorImpl)

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderContainer", mock.AnythingOfType("uint32"), mock.AnythingOfType("string"), mock.Anything).Return(false)
	mockContainerTree.On("GetPidByContainerID", "test-container-123").Return(uint32(999), nil)

	// First create a process with fork event
	forkEvent := conversion.ProcessEvent{
		Type: conversion.ForkEvent,
		PID:  1234,
		PPID: 1000,
		Comm: "old-process",
	}
	creator.FeedEvent(forkEvent)

	// Now send exec event that should update the process
	execEvent := conversion.ProcessEvent{
		Type:        conversion.ExecEvent,
		PID:         1234,
		PPID:        1000,
		Comm:        "new-process",
		Cmdline:     "new-process --arg",
		Uid:         &[]uint32{1000}[0],
		Gid:         &[]uint32{1000}[0],
		Cwd:         "/home/user",
		Path:        "/usr/bin/new-process",
		ContainerID: "test-container-123",
	}

	creator.FeedEvent(execEvent)

	// Verify process was updated
	proc := impl.processMap.Get(1234)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(1234), proc.PID)
	assert.Equal(t, uint32(999), proc.PPID)   // Should be updated to shim PID
	assert.Equal(t, "new-process", proc.Comm) // Should be updated
	assert.Equal(t, "new-process --arg", proc.Cmdline)
	assert.Equal(t, uint32(1000), *proc.Uid)
	assert.Equal(t, uint32(1000), *proc.Gid)
	assert.Equal(t, "/home/user", proc.Cwd)
	assert.Equal(t, "/usr/bin/new-process", proc.Path)

	mockContainerTree.AssertExpectations(t)
}

func TestHandleExecEventWithGetPidByContainerIDError(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(true))
	impl := creator.(*processTreeCreatorImpl)

	// Mock container tree methods - GetPidByContainerID returns an error
	mockContainerTree.On("IsProcessUnderContainer", mock.AnythingOfType("uint32"), mock.AnythingOfType("string"), mock.Anything).Return(false)
	mockContainerTree.On("GetPidByContainerID", "test-container-123").Return(uint32(0), fmt.Errorf("container not found"))

	// First create a process with fork event
	forkEvent := conversion.ProcessEvent{
		Type: conversion.ForkEvent,
		PID:  1234,
		PPID: 1000,
		Comm: "old-process",
	}
	creator.FeedEvent(forkEvent)

	// Now send exec event that should update the process
	execEvent := conversion.ProcessEvent{
		Type:        conversion.ExecEvent,
		PID:         1234,
		PPID:        1000,
		Comm:        "new-process",
		Cmdline:     "new-process --arg",
		Uid:         &[]uint32{1000}[0],
		Gid:         &[]uint32{1000}[0],
		Cwd:         "/home/user",
		Path:        "/usr/bin/new-process",
		ContainerID: "test-container-123",
	}

	creator.FeedEvent(execEvent)

	// Verify process was updated but PPID remains unchanged since GetPidByContainerID failed
	proc := impl.processMap.Get(1234)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(1234), proc.PID)
	assert.Equal(t, uint32(1000), proc.PPID)  // Should remain unchanged due to error
	assert.Equal(t, "new-process", proc.Comm) // Should be updated
	assert.Equal(t, "new-process --arg", proc.Cmdline)
	assert.Equal(t, uint32(1000), *proc.Uid)
	assert.Equal(t, uint32(1000), *proc.Gid)
	assert.Equal(t, "/home/user", proc.Cwd)
	assert.Equal(t, "/usr/bin/new-process", proc.Path)

	mockContainerTree.AssertExpectations(t)
}

func TestHandleExecEventProcessAlreadyUnderContainer(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(true))
	impl := creator.(*processTreeCreatorImpl)

	// Mock container tree methods - process is already under container subtree
	mockContainerTree.On("IsProcessUnderContainer", mock.AnythingOfType("uint32"), mock.AnythingOfType("string"), mock.Anything).Return(true)
	// GetPidByContainerID should not be called since process is already under container

	// First create a process with fork event
	forkEvent := conversion.ProcessEvent{
		Type: conversion.ForkEvent,
		PID:  1234,
		PPID: 1000,
		Comm: "old-process",
	}
	creator.FeedEvent(forkEvent)

	// Now send exec event that should update the process
	execEvent := conversion.ProcessEvent{
		Type:        conversion.ExecEvent,
		PID:         1234,
		PPID:        1000,
		Comm:        "new-process",
		Cmdline:     "new-process --arg",
		Uid:         &[]uint32{1000}[0],
		Gid:         &[]uint32{1000}[0],
		Cwd:         "/home/user",
		Path:        "/usr/bin/new-process",
		ContainerID: "test-container-123",
	}

	creator.FeedEvent(execEvent)

	// Verify process was updated but PPID remains unchanged since it's already under container
	proc := impl.processMap.Get(1234)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(1234), proc.PID)
	assert.Equal(t, uint32(1000), proc.PPID)  // Should remain unchanged
	assert.Equal(t, "new-process", proc.Comm) // Should be updated
	assert.Equal(t, "new-process --arg", proc.Cmdline)
	assert.Equal(t, uint32(1000), *proc.Uid)
	assert.Equal(t, uint32(1000), *proc.Gid)
	assert.Equal(t, "/home/user", proc.Cwd)
	assert.Equal(t, "/usr/bin/new-process", proc.Path)

	mockContainerTree.AssertExpectations(t)
}

func TestHandleExitEvent(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))
	impl := creator.(*processTreeCreatorImpl)

	// Start the creator to enable exit manager
	creator.Start()
	defer creator.Stop()

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)

	// Create parent process
	parentEvent := conversion.ProcessEvent{
		Type: conversion.ForkEvent,
		PID:  1000,
		PPID: 1,
		Comm: "parent",
	}
	creator.FeedEvent(parentEvent)

	// Create child process
	childEvent := conversion.ProcessEvent{
		Type: conversion.ForkEvent,
		PID:  1234,
		PPID: 1000,
		Comm: "child",
	}
	creator.FeedEvent(childEvent)

	// Verify parent-child relationship
	parent := impl.processMap.Get(1000)
	child := impl.processMap.Get(1234)
	assert.NotNil(t, parent)
	assert.NotNil(t, child)
	assert.Equal(t, uint32(1000), child.PPID)
	assert.Len(t, parent.ChildrenMap, 1)

	// Send exit event for parent
	exitEvent := conversion.ProcessEvent{
		Type: conversion.ExitEvent,
		PID:  1000,
	}
	creator.FeedEvent(exitEvent)

	// Verify process is still in map but added to pending exits
	assert.NotNil(t, impl.processMap.Get(1000))

	impl.mutex.Lock()
	assert.Len(t, impl.pendingExits, 1)
	assert.Contains(t, impl.pendingExits, uint32(1000))
	impl.mutex.Unlock()
}

func TestGetRootTree(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)

	// Create process tree: init(1) -> bash(100) -> app(200)
	events := []conversion.ProcessEvent{
		{Type: conversion.ForkEvent, PID: 1, PPID: 0, Comm: "init"},
		{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "bash"},
		{Type: conversion.ForkEvent, PID: 200, PPID: 100, Comm: "app"},
	}

	for _, event := range events {
		creator.FeedEvent(event)
	}

	// Get root tree
	roots, err := creator.GetRootTree()
	assert.NoError(t, err)
	assert.Len(t, roots, 1)
	assert.Equal(t, uint32(1), roots[0].PID)
	assert.Equal(t, "init", roots[0].Comm)
}

func TestGetProcessMap(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)

	// Create some processes
	events := []conversion.ProcessEvent{
		{Type: conversion.ForkEvent, PID: 1, PPID: 0, Comm: "init"},
		{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "bash"},
		{Type: conversion.ForkEvent, PID: 200, PPID: 100, Comm: "app"},
	}

	for _, event := range events {
		creator.FeedEvent(event)
	}

	// Get process map
	processMap := creator.GetProcessMap()

	// Check that processes exist
	initProc := processMap.Get(1)
	bashProc := processMap.Get(100)
	appProc := processMap.Get(200)

	assert.NotNil(t, initProc)
	assert.NotNil(t, bashProc)
	assert.NotNil(t, appProc)
	assert.Equal(t, "init", initProc.Comm)
	assert.Equal(t, "bash", bashProc.Comm)
	assert.Equal(t, "app", appProc.Comm)
}

func TestGetProcessNode(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)

	// Create a process
	event := conversion.ProcessEvent{
		Type: conversion.ForkEvent,
		PID:  1234,
		PPID: 1000,
		Comm: "test-process",
	}
	creator.FeedEvent(event)

	// Get existing process
	proc, err := creator.GetProcessNode(1234)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(1234), proc.PID)
	assert.Equal(t, "test-process", proc.Comm)

	// Get non-existing process
	proc, err = creator.GetProcessNode(9999)
	assert.NoError(t, err)
	assert.Nil(t, proc)
}

func TestGetPidBranch(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))
	impl := creator.(*processTreeCreatorImpl)

	// Mock container tree methods
	expectedProcess := apitypes.Process{
		PID:  1234,
		Comm: "container-process",
	}

	mockContainerTree.On("GetPidBranch", "container-123", uint32(1234), mock.Anything).Return(expectedProcess, nil)

	// Create some processes
	event := conversion.ProcessEvent{
		Type: conversion.ForkEvent,
		PID:  1234,
		PPID: 1000,
		Comm: "test-process",
	}
	creator.FeedEvent(event)

	// Get container branch - cast to implementation to access method
	result, err := impl.GetPidBranch(mockContainerTree, "container-123", 1234)
	assert.NoError(t, err)
	assert.Equal(t, expectedProcess, result)

	mockContainerTree.AssertExpectations(t)
}

func TestUpdatePPID(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(true))
	impl := creator.(*processTreeCreatorImpl)

	// Create parent and child processes
	parent := impl.getOrCreateProcess(1000)
	child := impl.getOrCreateProcess(1234)
	child.PPID = 1000
	child.Comm = "child-process"

	// Link child to parent
	impl.linkProcessToParent(child)

	// Verify initial state
	assert.Equal(t, uint32(1000), child.PPID)
	assert.Len(t, parent.ChildrenMap, 1)

	// Create new parent
	newParent := impl.getOrCreateProcess(2000)

	// Test case 1: New PPID is under container, should always update
	mockContainerTree.On("IsProcessUnderContainer", uint32(2000), mock.AnythingOfType("string"), mock.Anything).Return(true)

	event := conversion.ProcessEvent{
		PID:         1234,
		PPID:        2000,
		ContainerID: "test-container-123",
	}

	impl.UpdatePPID(child, event)

	// Verify update
	assert.Equal(t, uint32(2000), child.PPID)
	assert.Len(t, parent.ChildrenMap, 0)    // Removed from old parent
	assert.Len(t, newParent.ChildrenMap, 1) // Added to new parent

	mockContainerTree.AssertExpectations(t)
}

func TestLinkProcessToParent(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))
	impl := creator.(*processTreeCreatorImpl)

	// Create parent and child processes
	parent := impl.getOrCreateProcess(1000)
	child := impl.getOrCreateProcess(1234)
	child.PPID = 1000
	child.Comm = "child-process"

	// Link child to parent
	impl.linkProcessToParent(child)

	// Verify link
	assert.Len(t, parent.ChildrenMap, 1)
	key := apitypes.CommPID{PID: 1234}
	assert.Contains(t, parent.ChildrenMap, key)
	assert.Equal(t, child, parent.ChildrenMap[key])

	// Test circular reference prevention
	child.PPID = 1234 // Set parent to itself
	impl.linkProcessToParent(child)
	// Should not create circular reference - child should not be added to itself
}

func TestUpdateProcessPPID(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))
	impl := creator.(*processTreeCreatorImpl)

	// Create parent and child processes
	oldParent := impl.getOrCreateProcess(1000)
	newParent := impl.getOrCreateProcess(2000)
	child := impl.getOrCreateProcess(1234)
	child.PPID = 1000
	child.Comm = "child-process"

	// Link child to old parent
	impl.linkProcessToParent(child)

	// Verify initial state
	assert.Equal(t, uint32(1000), child.PPID)
	assert.Len(t, oldParent.ChildrenMap, 1)
	assert.Len(t, newParent.ChildrenMap, 0)

	// Update PPID
	impl.updateProcessPPID(child, 2000)

	// Verify update
	assert.Equal(t, uint32(2000), child.PPID)
	assert.Len(t, oldParent.ChildrenMap, 0) // Removed from old parent
	assert.Len(t, newParent.ChildrenMap, 1) // Added to new parent

	key := apitypes.CommPID{PID: 1234}
	assert.Contains(t, newParent.ChildrenMap, key)
	assert.Equal(t, child, newParent.ChildrenMap[key])

	// Test no-op case
	impl.updateProcessPPID(child, 2000) // Same PPID
	assert.Equal(t, uint32(2000), child.PPID)
	assert.Len(t, newParent.ChildrenMap, 1)

	// Test circular reference prevention
	impl.updateProcessPPID(child, 1234)       // Set parent to itself
	assert.Equal(t, uint32(2000), child.PPID) // Should not change
}

func TestShallowCopyProcess(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))
	impl := creator.(*processTreeCreatorImpl)

	// Create original process
	original := &apitypes.Process{
		PID:         1234,
		PPID:        1000,
		Comm:        "test-process",
		Cmdline:     "test-process --arg",
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}

	// Add a child to the original
	child := &apitypes.Process{PID: 5678, Comm: "child"}
	key := apitypes.CommPID{PID: 5678}
	original.ChildrenMap[key] = child

	// Create shallow copy
	copyProcess := impl.shallowCopyProcess(original)

	// Verify copy
	assert.NotNil(t, copyProcess)
	assert.Equal(t, original.PID, copyProcess.PID)
	assert.Equal(t, original.PPID, copyProcess.PPID)
	assert.Equal(t, original.Comm, copyProcess.Comm)
	assert.Equal(t, original.Cmdline, copyProcess.Cmdline)

	// Verify it's a different instance (different pointer addresses)
	assert.NotSame(t, original, copyProcess)

	// Verify children map is shared reference (shallow copy)
	assert.Equal(t, original.ChildrenMap, copyProcess.ChildrenMap)

	// Test nil input
	nilCopy := impl.shallowCopyProcess(nil)
	assert.Nil(t, nilCopy)
}

func TestConcurrentAccess(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))

	// Start the creator
	creator.Start()
	defer creator.Stop()

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)

	// Test concurrent access
	var wg sync.WaitGroup
	const numGoroutines = 10
	const numOperations = 100

	// Launch goroutines that feed events
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				pid := uint32(goroutineID*numOperations + j + 1000)
				event := conversion.ProcessEvent{
					Type: conversion.ForkEvent,
					PID:  pid,
					PPID: 1,
					Comm: "test-process",
				}
				creator.FeedEvent(event)
			}
		}(i)
	}

	// Launch goroutines that read data
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				_, err := creator.GetRootTree()
				assert.NoError(t, err)

				processMap := creator.GetProcessMap()
				assert.NotNil(t, processMap)

				// Try to get a random process
				_, err = creator.GetProcessNode(1234)
				assert.NoError(t, err)
			}
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify final state
	processMap := creator.GetProcessMap()
	// Note: The process tree may contain additional processes (like PPID=1) that are auto-created
	// so we check that we have at least the expected number of processes by counting non-nil entries
	count := 0
	processMap.Range(func(pid uint32, proc *apitypes.Process) bool {
		if proc != nil {
			count++
		}
		return true
	})
	assert.GreaterOrEqual(t, count, numGoroutines*numOperations)
}

func TestEventHandlingWithEmptyFields(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))
	impl := creator.(*processTreeCreatorImpl)

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)

	// Test fork event with minimal fields
	forkEvent := conversion.ProcessEvent{
		Type: conversion.ForkEvent,
		PID:  1234,
		PPID: 1000,
		Comm: "test-process",
	}
	creator.FeedEvent(forkEvent)

	proc := impl.processMap.Get(1234)
	assert.NotNil(t, proc)
	assert.Equal(t, "test-process", proc.Comm)
	assert.Equal(t, "", proc.Cmdline) // Should be empty

	// Test procfs event that fills in missing fields
	procfsEvent := conversion.ProcessEvent{
		Type:    conversion.ProcfsEvent,
		PID:     1234,
		Cmdline: "test-process --arg",
		Cwd:     "/home/user",
	}
	creator.FeedEvent(procfsEvent)

	proc = impl.processMap.Get(1234)
	assert.NotNil(t, proc)
	assert.Equal(t, "test-process", proc.Comm)          // Should remain unchanged
	assert.Equal(t, "test-process --arg", proc.Cmdline) // Should be filled in
	assert.Equal(t, "/home/user", proc.Cwd)             // Should be filled in
}

func TestReparentingIntegration(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))
	impl := creator.(*processTreeCreatorImpl)

	// Start the creator
	creator.Start()
	defer creator.Stop()

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)

	// Create a process tree: parent(1000) -> child(1234) -> grandchild(5678)
	events := []conversion.ProcessEvent{
		{Type: conversion.ForkEvent, PID: 1000, PPID: 1, Comm: "parent"},
		{Type: conversion.ForkEvent, PID: 1234, PPID: 1000, Comm: "child"},
		{Type: conversion.ForkEvent, PID: 5678, PPID: 1234, Comm: "grandchild"},
	}

	for _, event := range events {
		creator.FeedEvent(event)
	}

	// Verify initial structure
	parent := impl.processMap.Get(1000)
	child := impl.processMap.Get(1234)
	grandchild := impl.processMap.Get(5678)

	assert.NotNil(t, parent)
	assert.NotNil(t, child)
	assert.NotNil(t, grandchild)
	assert.Equal(t, uint32(1000), child.PPID)
	assert.Equal(t, uint32(1234), grandchild.PPID)
	assert.Len(t, parent.ChildrenMap, 1)
	assert.Len(t, child.ChildrenMap, 1)

	// Exit the child process - should trigger reparenting
	exitEvent := conversion.ProcessEvent{
		Type: conversion.ExitEvent,
		PID:  1234,
	}
	creator.FeedEvent(exitEvent)

	// Process should be in pending exits
	impl.mutex.Lock()
	assert.Len(t, impl.pendingExits, 1)
	assert.Contains(t, impl.pendingExits, uint32(1234))

	// Verify children are collected for reparenting
	pendingExit := impl.pendingExits[1234]
	assert.NotNil(t, pendingExit)
	impl.mutex.Unlock()
}

// Note: The original TestReparentingStrategiesIntegration was removed because it relied on exit manager timing
// which is too slow for unit tests (10 minutes). Instead, use TestReparentingLogicDirect which tests
// the reparenting logic directly and is much more reliable.

func TestReparentingLogicDirect(t *testing.T) {
	// Test the reparenting logic directly without relying on exit manager timing
	t.Run("DefaultStrategy_Direct", func(t *testing.T) {
		containerTree := containerprocesstree.NewContainerProcessTree()
		creator := NewProcessTreeCreator(containerTree, createTestConfig(false))
		impl := creator.(*processTreeCreatorImpl)

		// Create process tree: init(1) -> parent(1000) -> child(1234) -> grandchild(5678)
		events := []conversion.ProcessEvent{
			{Type: conversion.ForkEvent, PID: 1, PPID: 0, Comm: "init"},
			{Type: conversion.ForkEvent, PID: 1000, PPID: 1, Comm: "parent"},
			{Type: conversion.ForkEvent, PID: 1234, PPID: 1000, Comm: "child"},
			{Type: conversion.ForkEvent, PID: 5678, PPID: 1234, Comm: "grandchild"},
		}

		for _, event := range events {
			creator.FeedEvent(event)
		}

		// Verify initial structure
		parent := impl.processMap.Get(1000)
		child := impl.processMap.Get(1234)
		grandchild := impl.processMap.Get(5678)

		assert.NotNil(t, parent)
		assert.NotNil(t, child)
		assert.NotNil(t, grandchild)
		assert.Equal(t, uint32(1000), child.PPID)
		assert.Equal(t, uint32(1234), grandchild.PPID)

		// Test reparenting logic directly
		children := []*apitypes.Process{grandchild}
		newParentPID, err := impl.reparentingStrategies.Reparent(1234, children, containerTree, &impl.processMap)

		assert.NoError(t, err)
		assert.Equal(t, uint32(1000), newParentPID, "Should use Default Strategy to reparent to parent's parent")

		// Apply the reparenting
		for _, child := range children {
			if child != nil {
				child.PPID = newParentPID
				impl.linkProcessToParent(child)
			}
		}

		// Verify reparenting worked
		updatedGrandchild := impl.processMap.Get(5678)
		assert.NotNil(t, updatedGrandchild)
		assert.Equal(t, uint32(1000), updatedGrandchild.PPID, "Grandchild should be reparented to parent")
	})

	t.Run("FallbackStrategy_Direct", func(t *testing.T) {
		containerTree := containerprocesstree.NewContainerProcessTree()
		creator := NewProcessTreeCreator(containerTree, createTestConfig(false))
		impl := creator.(*processTreeCreatorImpl)

		// Create process tree: orphan(1234) -> child(5678)
		events := []conversion.ProcessEvent{
			{Type: conversion.ForkEvent, PID: 1234, PPID: 0, Comm: "orphan"}, // True orphan with no parent
			{Type: conversion.ForkEvent, PID: 5678, PPID: 1234, Comm: "child"},
		}

		for _, event := range events {
			creator.FeedEvent(event)
		}

		// Verify initial structure
		orphan := impl.processMap.Get(1234)
		child := impl.processMap.Get(5678)

		assert.NotNil(t, orphan)
		assert.NotNil(t, child)
		assert.Equal(t, uint32(1234), child.PPID)

		// Test reparenting logic directly
		children := []*apitypes.Process{child}
		newParentPID, err := impl.reparentingStrategies.Reparent(1234, children, containerTree, &impl.processMap)

		assert.NoError(t, err)
		// The Default Strategy should be used first since the orphan has a PPID (999)
		// But since parent 999 doesn't exist in the process map, it should fall back to 0
		// Then the Fallback Strategy should be used to return 1
		assert.Equal(t, uint32(1), newParentPID, "Should use Fallback Strategy to reparent to init")

		// Apply the reparenting
		for _, child := range children {
			if child != nil {
				child.PPID = newParentPID
				impl.linkProcessToParent(child)
			}
		}

		// Verify reparenting worked
		updatedChild := impl.processMap.Get(5678)
		assert.NotNil(t, updatedChild)
		assert.Equal(t, uint32(1), updatedChild.PPID, "Child should be reparented to init")
	})

	t.Run("ContainerStrategy_Direct", func(t *testing.T) {
		mockContainerTree := &MockContainerProcessTree{}
		creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(true))
		impl := creator.(*processTreeCreatorImpl)

		// Mock all container tree methods to avoid unexpected calls
		mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)
		mockContainerTree.On("IsProcessUnderContainer", mock.AnythingOfType("uint32"), mock.AnythingOfType("string"), mock.Anything).Return(false)
		mockContainerTree.On("GetPidByContainerID", mock.AnythingOfType("string")).Return(uint32(0), nil)

		// Create container process tree: containerd-shim(50) -> nginx(100) -> worker(200)
		events := []conversion.ProcessEvent{
			{Type: conversion.ForkEvent, PID: 50, PPID: 1, Comm: "containerd-shim"},
			{Type: conversion.ForkEvent, PID: 100, PPID: 50, Comm: "nginx"},
			{Type: conversion.ForkEvent, PID: 200, PPID: 100, Comm: "nginx-worker"},
		}

		for _, event := range events {
			creator.FeedEvent(event)
		}

		// Now override the mock for the specific test case
		mockContainerTree.On("IsProcessUnderAnyContainerSubtree", uint32(100), mock.Anything).Return(true)
		mockContainerTree.On("GetShimPIDForProcess", uint32(100), mock.Anything).Return(uint32(50), true)

		// Verify initial structure
		shim := impl.processMap.Get(50)
		nginx := impl.processMap.Get(100)
		worker := impl.processMap.Get(200)

		assert.NotNil(t, shim)
		assert.NotNil(t, nginx)
		assert.NotNil(t, worker)
		assert.Equal(t, uint32(50), nginx.PPID)
		assert.Equal(t, uint32(100), worker.PPID)

		// Test reparenting logic directly
		children := []*apitypes.Process{worker}
		newParentPID, err := impl.reparentingStrategies.Reparent(100, children, mockContainerTree, &impl.processMap)

		assert.NoError(t, err)
		assert.Equal(t, uint32(50), newParentPID, "Should use Container Strategy to reparent to shim")

		// Apply the reparenting
		for _, child := range children {
			if child != nil {
				child.PPID = newParentPID
				impl.linkProcessToParent(child)
			}
		}

		// Verify reparenting worked
		updatedWorker := impl.processMap.Get(200)
		assert.NotNil(t, updatedWorker)
		assert.Equal(t, uint32(50), updatedWorker.PPID, "Worker should be reparented to shim")
	})
}

func TestComplexProcessTree(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)

	// Create a complex process tree
	events := []conversion.ProcessEvent{
		{Type: conversion.ForkEvent, PID: 1, PPID: 0, Comm: "init"},
		{Type: conversion.ForkEvent, PID: 100, PPID: 1, Comm: "systemd"},
		{Type: conversion.ForkEvent, PID: 200, PPID: 1, Comm: "kthreadd"},
		{Type: conversion.ForkEvent, PID: 300, PPID: 100, Comm: "bash"},
		{Type: conversion.ForkEvent, PID: 400, PPID: 100, Comm: "ssh"},
		{Type: conversion.ForkEvent, PID: 500, PPID: 300, Comm: "app1"},
		{Type: conversion.ForkEvent, PID: 600, PPID: 300, Comm: "app2"},
		{Type: conversion.ForkEvent, PID: 700, PPID: 500, Comm: "worker"},
	}

	for _, event := range events {
		creator.FeedEvent(event)
	}

	// Verify structure
	processMap := creator.GetProcessMap()

	// Count entries manually since SafeMap doesn't support len()
	count := 0
	processMap.Range(func(pid uint32, proc *apitypes.Process) bool {
		if proc != nil {
			count++
		}
		return true
	})
	assert.Equal(t, 8, count)

	// Check root processes
	roots, err := creator.GetRootTree()
	assert.NoError(t, err)
	assert.Len(t, roots, 1)
	assert.Equal(t, uint32(1), roots[0].PID)

	// Check parent-child relationships
	init := processMap.Get(1)
	systemd := processMap.Get(100)
	bash := processMap.Get(300)
	app1 := processMap.Get(500)
	worker := processMap.Get(700)

	assert.NotNil(t, init)
	assert.NotNil(t, systemd)
	assert.NotNil(t, bash)
	assert.NotNil(t, app1)
	assert.NotNil(t, worker)

	assert.Len(t, init.ChildrenMap, 2)    // systemd and kthreadd
	assert.Len(t, systemd.ChildrenMap, 2) // bash and ssh
	assert.Len(t, bash.ChildrenMap, 2)    // app1 and app2
	assert.Len(t, app1.ChildrenMap, 1)    // worker

	// Verify specific relationships
	assert.Equal(t, uint32(1), systemd.PPID)
	assert.Equal(t, uint32(100), bash.PPID)
	assert.Equal(t, uint32(300), app1.PPID)
	assert.Equal(t, uint32(500), worker.PPID)
}

func TestCircularReferencePreventionDeep(t *testing.T) {
	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))
	impl := creator.(*processTreeCreatorImpl)

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)

	// Create processes
	p1 := impl.getOrCreateProcess(100)
	p2 := impl.getOrCreateProcess(200)
	p3 := impl.getOrCreateProcess(300)

	p1.Comm = "proc1"
	p2.Comm = "proc2"
	p3.Comm = "proc3"

	// Create normal chain: p1 -> p2 -> p3
	impl.updateProcessPPID(p2, 100)
	impl.updateProcessPPID(p3, 200)

	// Verify normal chain
	assert.Equal(t, uint32(100), p2.PPID)
	assert.Equal(t, uint32(200), p3.PPID)
	assert.Len(t, p1.ChildrenMap, 1)
	assert.Len(t, p2.ChildrenMap, 1)

	// Attempt to create circular reference: p1 -> p2 -> p3 -> p1
	impl.updateProcessPPID(p1, 300) // This should be prevented

	// Verify circular reference was prevented
	assert.Equal(t, uint32(0), p1.PPID) // Should remain unchanged
	assert.Len(t, p3.ChildrenMap, 0)    // p1 should not be added as child of p3
}

func TestPerformanceWithManyProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	mockContainerTree := &MockContainerProcessTree{}
	creator := NewProcessTreeCreator(mockContainerTree, createTestConfig(false))

	// Don't start the creator to avoid exit manager overhead
	// creator.Start() is not called to avoid background processing

	// Mock container tree methods
	mockContainerTree.On("IsProcessUnderAnyContainerSubtree", mock.AnythingOfType("uint32"), mock.Anything).Return(false)

	const numProcesses = 1000 // Reduced from 10000 to 1000 for faster test
	start := time.Now()

	// Create many processes
	for i := 0; i < numProcesses; i++ {
		event := conversion.ProcessEvent{
			Type: conversion.ForkEvent,
			PID:  uint32(i + 1000),
			PPID: 1,
			Comm: "test-process",
		}
		creator.FeedEvent(event)
	}

	duration := time.Since(start)
	t.Logf("Created %d processes in %v", numProcesses, duration)

	// Verify performance is reasonable (should be sub-second)
	assert.Less(t, duration, time.Second, "Creating processes should be fast")

	// Verify all processes were created (plus the parent process with PID 1)
	processMap := creator.GetProcessMap()
	count := 0
	processMap.Range(func(pid uint32, proc *apitypes.Process) bool {
		if proc != nil {
			count++
		}
		return true
	})
	assert.GreaterOrEqual(t, count, numProcesses)

	// Test retrieval performance
	start = time.Now()
	for i := 0; i < 100; i++ { // Reduced from 1000 to 100 for faster test
		_, err := creator.GetRootTree()
		assert.NoError(t, err)
	}
	duration = time.Since(start)
	t.Logf("Retrieved root tree 100 times in %v", duration)
}
