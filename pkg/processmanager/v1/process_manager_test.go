package processmanager

import (
	"context"
	"fmt"
	"sync"
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

// Helper function type definition
type mockProcessAdder func(pid int, ppid uint32, comm string)

// Updated setup function with correct return types
func setupTestProcessManager(t *testing.T) (*ProcessManager, mockProcessAdder) {
	ctx, cancel := context.WithCancel(context.Background())
	pm := CreateProcessManager(ctx)

	// Create process mock map
	mockProcesses := make(map[int]apitypes.Process)

	// Store original function
	originalGetProcessFromProc := pm.getProcessFromProc

	// Replace with mock version
	pm.getProcessFromProc = func(pid int) (apitypes.Process, error) {
		if proc, exists := mockProcesses[pid]; exists {
			return proc, nil
		}
		return apitypes.Process{}, fmt.Errorf("mock process not found: %d", pid)
	}

	// Set up cleanup
	t.Cleanup(func() {
		cancel()
		pm.getProcessFromProc = originalGetProcessFromProc
	})

	// Return the process manager and the mock process adder function
	return pm, func(pid int, ppid uint32, comm string) {
		uid := uint32(1000)
		gid := uint32(1000)
		mockProcesses[pid] = apitypes.Process{
			PID:     uint32(pid),
			PPID:    ppid,
			Comm:    comm,
			Cmdline: comm,
			Uid:     &uid,
			Gid:     &gid,
		}
	}
}

func TestProcessManagerBasics(t *testing.T) {
	pm, addMockProcess := setupTestProcessManager(t)

	containerID := "test-container-1"
	shimPID := uint32(999)
	containerPID := uint32(1000)

	// Add mock container process with shim as parent
	addMockProcess(int(containerPID), shimPID, "container-main")

	// Register container
	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:  containerID,
					ContainerPID: containerPID,
				},
			},
		},
	})

	// Verify shim was recorded
	assert.True(t, pm.containerIdToShimPid.Has(containerID))
	assert.Equal(t, shimPID, pm.containerIdToShimPid.Get(containerID))

	// Verify container process was added
	containerProc, exists := pm.processTree.Load(containerPID)
	assert.True(t, exists)
	assert.Equal(t, shimPID, containerProc.PPID)
}

func TestProcessTracking(t *testing.T) {
	pm, addMockProcess := setupTestProcessManager(t)

	containerID := "test-container-1"
	shimPID := uint32(999)
	containerPID := uint32(1000)

	addMockProcess(int(containerPID), shimPID, "container-main")

	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:  containerID,
					ContainerPID: containerPID,
				},
			},
		},
	})

	testCases := []struct {
		name   string
		event  tracerexectype.Event
		verify func(t *testing.T, pm *ProcessManager)
	}{
		{
			name: "Container child process",
			event: tracerexectype.Event{
				Pid:  1001,
				Ppid: containerPID,
				Comm: "nginx",
				Args: []string{"nginx", "-g", "daemon off;"},
			},
			verify: func(t *testing.T, pm *ProcessManager) {
				proc, exists := pm.processTree.Load(1001)
				require.True(t, exists)
				assert.Equal(t, containerPID, proc.PPID)
				assert.Equal(t, "nginx", proc.Comm)
			},
		},
		{
			name: "Exec process (direct child of shim)",
			event: tracerexectype.Event{
				Pid:  1002,
				Ppid: shimPID,
				Comm: "bash",
				Args: []string{"bash"},
			},
			verify: func(t *testing.T, pm *ProcessManager) {
				proc, exists := pm.processTree.Load(1002)
				require.True(t, exists)
				assert.Equal(t, shimPID, proc.PPID)
				assert.Equal(t, "bash", proc.Comm)
			},
		},
		{
			name: "Nested process",
			event: tracerexectype.Event{
				Pid:  1003,
				Ppid: 1001,
				Comm: "nginx-worker",
				Args: []string{"nginx", "worker process"},
			},
			verify: func(t *testing.T, pm *ProcessManager) {
				proc, exists := pm.processTree.Load(1003)
				require.True(t, exists)
				assert.Equal(t, uint32(1001), proc.PPID)

				parent, exists := pm.processTree.Load(1001)
				require.True(t, exists)
				hasChild := false
				for _, child := range parent.Children {
					if child.PID == 1003 {
						hasChild = true
						break
					}
				}
				assert.True(t, hasChild)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pm.ReportEvent(utils.ExecveEventType, &tc.event)
			tc.verify(t, pm)
		})
	}
}

func TestProcessRemoval(t *testing.T) {
	pm, addMockProcess := setupTestProcessManager(t)

	containerID := "test-container-1"
	shimPID := uint32(999)
	containerPID := uint32(1000)

	addMockProcess(int(containerPID), shimPID, "container-main")

	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:  containerID,
					ContainerPID: containerPID,
				},
			},
		},
	})

	// Create a process tree
	processes := []struct {
		pid  uint32
		ppid uint32
		comm string
	}{
		{1001, containerPID, "parent"},
		{1002, 1001, "child1"},
		{1003, 1002, "grandchild1"},
		{1004, 1002, "grandchild2"},
	}

	// Add processes
	for _, proc := range processes {
		event := &tracerexectype.Event{
			Pid:  proc.pid,
			Ppid: proc.ppid,
			Comm: proc.comm,
		}
		pm.ReportEvent(utils.ExecveEventType, event)
	}

	// Verify initial structure
	for _, proc := range processes {
		assert.True(t, pm.processTree.Has(proc.pid))
	}

	// Remove middle process and verify tree reorganization
	pm.removeProcess(1002)

	// Verify process was removed
	assert.False(t, pm.processTree.Has(1002))

	// Verify children were reassigned to parent
	parent, exists := pm.processTree.Load(1001)
	require.True(t, exists)

	// Should now have both grandchildren
	childPIDs := make(map[uint32]bool)
	for _, child := range parent.Children {
		childPIDs[child.PID] = true
	}
	assert.True(t, childPIDs[1003])
	assert.True(t, childPIDs[1004])

	// Verify grandchildren's PPID was updated
	for _, pid := range []uint32{1003, 1004} {
		proc, exists := pm.processTree.Load(pid)
		require.True(t, exists)
		assert.Equal(t, uint32(1001), proc.PPID)
	}
}

func TestContainerRemoval(t *testing.T) {
	pm, addMockProcess := setupTestProcessManager(t)

	containerID := "test-container-1"
	shimPID := uint32(999)
	containerPID := uint32(1000)

	addMockProcess(int(containerPID), shimPID, "container-main")

	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:  containerID,
					ContainerPID: containerPID,
				},
			},
		},
	})

	// Create various processes under the container
	processes := []struct {
		pid  uint32
		ppid uint32
		comm string
	}{
		{containerPID, shimPID, "container-main"},
		{1001, containerPID, "app"},
		{1002, 1001, "worker"},
		{1003, shimPID, "exec"}, // direct child of shim
	}

	for _, proc := range processes {
		event := &tracerexectype.Event{
			Pid:  proc.pid,
			Ppid: proc.ppid,
			Comm: proc.comm,
		}
		pm.ReportEvent(utils.ExecveEventType, event)
	}

	// Remove container
	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeRemoveContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:  containerID,
					ContainerPID: containerPID,
				},
			},
		},
	})

	// Verify all processes were removed
	for _, proc := range processes {
		assert.False(t, pm.processTree.Has(proc.pid))
	}

	// Verify container was removed from mapping
	assert.False(t, pm.containerIdToShimPid.Has(containerID))
}

func TestMultipleContainers(t *testing.T) {
	pm, addMockProcess := setupTestProcessManager(t)

	containers := []struct {
		id           string
		shimPID      uint32
		containerPID uint32
	}{
		{"container-1", 999, 1000},
		{"container-2", 1998, 2000},
	}

	// Add containers
	for _, c := range containers {
		addMockProcess(int(c.containerPID), c.shimPID, fmt.Sprintf("container-%s", c.id))

		pm.ContainerCallback(containercollection.PubSubEvent{
			Type: containercollection.EventTypeAddContainer,
			Container: &containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerID:  c.id,
						ContainerPID: c.containerPID,
					},
				},
			},
		})

		// Add some processes to each container
		event1 := &tracerexectype.Event{
			Pid:  c.containerPID + 1,
			Ppid: c.containerPID,
			Comm: "process-1",
		}
		event2 := &tracerexectype.Event{
			Pid:  c.containerPID + 2,
			Ppid: c.shimPID,
			Comm: "exec-process",
		}

		pm.ReportEvent(utils.ExecveEventType, event1)
		pm.ReportEvent(utils.ExecveEventType, event2)
	}

	// Verify each container's processes
	for _, c := range containers {
		// Check container process
		proc, exists := pm.processTree.Load(c.containerPID)
		require.True(t, exists)
		assert.Equal(t, c.shimPID, proc.PPID)

		// Check child process
		childProc, exists := pm.processTree.Load(c.containerPID + 1)
		require.True(t, exists)
		assert.Equal(t, c.containerPID, childProc.PPID)

		// Check exec process
		execProc, exists := pm.processTree.Load(c.containerPID + 2)
		require.True(t, exists)
		assert.Equal(t, c.shimPID, execProc.PPID)
	}

	// Remove first container
	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeRemoveContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:  containers[0].id,
					ContainerPID: containers[0].containerPID,
				},
			},
		},
	})

	// Verify first container's processes are gone
	assert.False(t, pm.processTree.Has(containers[0].containerPID))
	assert.False(t, pm.processTree.Has(containers[0].containerPID+1))
	assert.False(t, pm.processTree.Has(containers[0].containerPID+2))

	// Verify second container's processes remain
	assert.True(t, pm.processTree.Has(containers[1].containerPID))
	assert.True(t, pm.processTree.Has(containers[1].containerPID+1))
	assert.True(t, pm.processTree.Has(containers[1].containerPID+2))
}

func TestErrorCases(t *testing.T) {
	pm, addMockProcess := setupTestProcessManager(t)

	t.Run("get non-existent process tree", func(t *testing.T) {
		_, err := pm.GetProcessTreeForPID("non-existent", 1000)
		assert.Error(t, err)
	})

	t.Run("process with non-existent parent", func(t *testing.T) {
		containerID := "test-container"
		shimPID := uint32(999)
		containerPID := uint32(1000)

		addMockProcess(int(containerPID), shimPID, "container-main")

		pm.ContainerCallback(containercollection.PubSubEvent{
			Type: containercollection.EventTypeAddContainer,
			Container: &containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerID:  containerID,
						ContainerPID: containerPID,
					},
				},
			},
		})

		// Add process with non-existent parent
		event := &tracerexectype.Event{
			Pid:  2000,
			Ppid: 1500, // Non-existent PPID
			Comm: "orphan",
		}
		pm.ReportEvent(utils.ExecveEventType, event)

		// Process should still be added
		assert.True(t, pm.processTree.Has(2000))
	})
}

func TestRaceConditions(t *testing.T) {
	pm, addMockProcess := setupTestProcessManager(t)

	containerID := "test-container"
	shimPID := uint32(999)
	containerPID := uint32(1000)

	// Setup container
	addMockProcess(int(containerPID), shimPID, "container-main")
	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:  containerID,
					ContainerPID: containerPID,
				},
			},
		},
	})

	processCount := 100
	var mu sync.Mutex
	processStates := make(map[uint32]struct {
		added   bool
		removed bool
	})

	// Pre-populate process states
	for i := 0; i < processCount; i++ {
		pid := uint32(2000 + i)
		processStates[pid] = struct {
			added   bool
			removed bool
		}{false, false}
	}

	// Channel to signal between goroutines
	removeDone := make(chan bool)
	addDone := make(chan bool)

	// Goroutine to remove processes (run first)
	go func() {
		for i := 0; i < processCount; i++ {
			if i%2 == 0 {
				pid := uint32(2000 + i)
				mu.Lock()
				if state, exists := processStates[pid]; exists {
					state.removed = true
					processStates[pid] = state
				}
				mu.Unlock()
				pm.removeProcess(pid)
			}
		}
		removeDone <- true
	}()

	// Wait for removals to complete before starting additions
	<-removeDone

	// Goroutine to add processes
	go func() {
		for i := 0; i < processCount; i++ {
			pid := uint32(2000 + i)
			// Only add if not marked for removal
			mu.Lock()
			state := processStates[pid]
			if !state.removed {
				event := &tracerexectype.Event{
					Pid:  pid,
					Ppid: shimPID,
					Comm: fmt.Sprintf("process-%d", i),
				}
				state.added = true
				processStates[pid] = state
				mu.Unlock()
				pm.ReportEvent(utils.ExecveEventType, event)
			} else {
				mu.Unlock()
			}
		}
		addDone <- true
	}()

	// Wait for additions to complete
	<-addDone

	// Verify final state
	remainingCount := 0
	pm.processTree.Range(func(pid uint32, process apitypes.Process) bool {
		if pid >= 2000 && pid < 2000+uint32(processCount) {
			mu.Lock()
			state := processStates[pid]
			mu.Unlock()

			if state.removed {
				t.Errorf("Process %d exists but was marked for removal", pid)
			}
			if !state.added {
				t.Errorf("Process %d exists but was not marked as added", pid)
			}
			remainingCount++
		}
		return true
	})

	// Verify all processes marked as removed are actually gone
	mu.Lock()
	for pid, state := range processStates {
		if state.removed {
			if pm.processTree.Has(pid) {
				t.Errorf("Process %d was marked for removal but still exists", pid)
			}
		} else if state.added {
			if !pm.processTree.Has(pid) {
				t.Errorf("Process %d was marked as added but doesn't exist", pid)
			}
		}
	}
	mu.Unlock()

	// We expect exactly half of the processes to remain (odd-numbered ones)
	expectedCount := processCount / 2
	assert.Equal(t, expectedCount, remainingCount,
		"Expected exactly %d processes, got %d", expectedCount, remainingCount)

	// Verify all remaining processes have correct parent
	pm.processTree.Range(func(pid uint32, process apitypes.Process) bool {
		if pid >= 2000 && pid < 2000+uint32(processCount) {
			assert.Equal(t, shimPID, process.PPID,
				"Process %d should have shim as parent", pid)
		}
		return true
	})
}

func TestDuplicateProcessHandling(t *testing.T) {
	pm, addMockProcess := setupTestProcessManager(t)

	containerID := "test-container"
	shimPID := uint32(999)
	containerPID := uint32(1000)

	// Setup container
	addMockProcess(int(containerPID), shimPID, "container-main")
	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:  containerID,
					ContainerPID: containerPID,
				},
			},
		},
	})

	t.Run("update process with same parent", func(t *testing.T) {
		// First add a parent process
		parentEvent := &tracerexectype.Event{
			Pid:  1001,
			Ppid: containerPID,
			Comm: "parent-process",
			Args: []string{"parent-process", "--initial"},
		}
		pm.ReportEvent(utils.ExecveEventType, parentEvent)

		// Add child process
		childEvent := &tracerexectype.Event{
			Pid:  1002,
			Ppid: 1001,
			Comm: "child-process",
			Args: []string{"child-process", "--initial"},
		}
		pm.ReportEvent(utils.ExecveEventType, childEvent)

		// Verify initial state
		parent, exists := pm.processTree.Load(1001)
		require.True(t, exists)
		assert.Equal(t, "parent-process", parent.Comm)
		assert.Equal(t, "parent-process --initial", parent.Cmdline)
		assert.Len(t, parent.Children, 1)
		assert.Equal(t, uint32(1002), parent.Children[0].PID)

		// Add same child process again with different arguments
		updatedChildEvent := &tracerexectype.Event{
			Pid:  1002,
			Ppid: 1001,
			Comm: "child-process",
			Args: []string{"child-process", "--updated"},
		}
		pm.ReportEvent(utils.ExecveEventType, updatedChildEvent)

		// Verify the process was updated
		updatedChild, exists := pm.processTree.Load(1002)
		require.True(t, exists)
		assert.Equal(t, "child-process --updated", updatedChild.Cmdline)

		// Verify parent's children list was updated
		updatedParent, exists := pm.processTree.Load(1001)
		require.True(t, exists)
		assert.Len(t, updatedParent.Children, 1)
		assert.Equal(t, "child-process --updated", updatedParent.Children[0].Cmdline)
	})

	t.Run("update process with different parent", func(t *testing.T) {
		// Move process to different parent
		differentParentEvent := &tracerexectype.Event{
			Pid:  1002,
			Ppid: containerPID,
			Comm: "child-process",
			Args: []string{"child-process", "--new-parent"},
		}
		pm.ReportEvent(utils.ExecveEventType, differentParentEvent)

		// Verify process was updated with new parent
		movedChild, exists := pm.processTree.Load(1002)
		require.True(t, exists)
		assert.Equal(t, containerPID, movedChild.PPID)
		assert.Equal(t, "child-process --new-parent", movedChild.Cmdline)

		// Verify old parent no longer has the child
		oldParent, exists := pm.processTree.Load(1001)
		require.True(t, exists)
		assert.Empty(t, oldParent.Children, "Old parent should have no children")

		// Verify new parent has the child
		containerProcess, exists := pm.processTree.Load(containerPID)
		require.True(t, exists)
		hasChild := false
		for _, child := range containerProcess.Children {
			if child.PID == 1002 {
				hasChild = true
				assert.Equal(t, "child-process --new-parent", child.Cmdline)
			}
		}
		assert.True(t, hasChild, "New parent should have the child")
	})
}

func TestProcessReparenting(t *testing.T) {
	pm, addMockProcess := setupTestProcessManager(t)

	containerID := "test-container"
	shimPID := uint32(999)
	containerPID := uint32(1000)

	// Setup container
	addMockProcess(int(containerPID), shimPID, "container-main")
	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:  containerID,
					ContainerPID: containerPID,
				},
			},
		},
	})

	t.Run("reparent to nearest living ancestor", func(t *testing.T) {
		// Create a chain of processes:
		// shim -> grandparent -> parent -> child

		// Create grandparent process
		grandparentPID := uint32(2000)
		grandparentEvent := &tracerexectype.Event{
			Pid:  grandparentPID,
			Ppid: shimPID,
			Comm: "grandparent",
			Args: []string{"grandparent"},
		}
		pm.ReportEvent(utils.ExecveEventType, grandparentEvent)

		// Create parent process
		parentPID := uint32(2001)
		parentEvent := &tracerexectype.Event{
			Pid:  parentPID,
			Ppid: grandparentPID,
			Comm: "parent",
			Args: []string{"parent"},
		}
		pm.ReportEvent(utils.ExecveEventType, parentEvent)

		// Create child process
		childPID := uint32(2002)
		childEvent := &tracerexectype.Event{
			Pid:  childPID,
			Ppid: parentPID,
			Comm: "child",
			Args: []string{"child"},
		}
		pm.ReportEvent(utils.ExecveEventType, childEvent)

		// Verify initial hierarchy
		child, exists := pm.processTree.Load(childPID)
		require.True(t, exists)
		assert.Equal(t, parentPID, child.PPID)

		parent, exists := pm.processTree.Load(parentPID)
		require.True(t, exists)
		assert.Equal(t, grandparentPID, parent.PPID)

		// When parent dies, child should be reparented to grandparent
		pm.removeProcess(parentPID)

		// Verify child was reparented to grandparent
		child, exists = pm.processTree.Load(childPID)
		require.True(t, exists)
		assert.Equal(t, grandparentPID, child.PPID, "Child should be reparented to grandparent")

		// Verify grandparent has the child in its children list
		grandparent, exists := pm.processTree.Load(grandparentPID)
		require.True(t, exists)
		hasChild := false
		for _, c := range grandparent.Children {
			if c.PID == childPID {
				hasChild = true
				break
			}
		}
		assert.True(t, hasChild, "Grandparent should have the reparented child")

		// Now if grandparent dies too, child should be reparented to shim
		pm.removeProcess(grandparentPID)

		child, exists = pm.processTree.Load(childPID)
		require.True(t, exists)
		assert.Equal(t, shimPID, child.PPID, "Child should be reparented to shim when grandparent dies")
	})

	t.Run("reparent multiple children", func(t *testing.T) {
		// Create a parent with multiple children
		parentPID := uint32(3000)
		parentEvent := &tracerexectype.Event{
			Pid:  parentPID,
			Ppid: shimPID,
			Comm: "parent",
			Args: []string{"parent"},
		}
		pm.ReportEvent(utils.ExecveEventType, parentEvent)

		// Create several children
		childPIDs := []uint32{3001, 3002, 3003}
		for _, pid := range childPIDs {
			childEvent := &tracerexectype.Event{
				Pid:  pid,
				Ppid: parentPID,
				Comm: fmt.Sprintf("child-%d", pid),
				Args: []string{"child"},
			}
			pm.ReportEvent(utils.ExecveEventType, childEvent)
		}

		// Create a subprocess under one of the children
		grandchildPID := uint32(3004)
		grandchildEvent := &tracerexectype.Event{
			Pid:  grandchildPID,
			Ppid: childPIDs[0],
			Comm: "grandchild",
			Args: []string{"grandchild"},
		}
		pm.ReportEvent(utils.ExecveEventType, grandchildEvent)

		// When parent dies, all direct children should be reparented to shim
		pm.removeProcess(parentPID)

		// Verify all children were reparented to shim
		for _, childPID := range childPIDs {
			child, exists := pm.processTree.Load(childPID)
			require.True(t, exists)
			assert.Equal(t, shimPID, child.PPID, "Child should be reparented to shim")
		}

		// When first child dies, its grandchild should be reparented to shim too
		pm.removeProcess(childPIDs[0])

		grandchild, exists := pm.processTree.Load(grandchildPID)
		require.True(t, exists)
		assert.Equal(t, shimPID, grandchild.PPID, "Grandchild should be reparented to shim")
	})
}

func TestRemoveProcessesUnderShim(t *testing.T) {
	tests := []struct {
		name         string
		initialTree  map[uint32]apitypes.Process
		shimPID      uint32
		expectedTree map[uint32]apitypes.Process
		description  string
	}{
		{
			name: "simple_process_tree",
			initialTree: map[uint32]apitypes.Process{
				100: {PID: 100, PPID: 1, Comm: "shim", Children: []apitypes.Process{}},     // shim process
				200: {PID: 200, PPID: 100, Comm: "parent", Children: []apitypes.Process{}}, // direct child of shim
				201: {PID: 201, PPID: 200, Comm: "child1", Children: []apitypes.Process{}}, // child of parent
				202: {PID: 202, PPID: 200, Comm: "child2", Children: []apitypes.Process{}}, // another child of parent
			},
			shimPID: 100,
			expectedTree: map[uint32]apitypes.Process{
				100: {PID: 100, PPID: 1, Comm: "shim", Children: []apitypes.Process{}}, // only shim remains
			},
			description: "Should remove all processes under shim including children of children",
		},
		{
			name:         "empty_tree",
			initialTree:  map[uint32]apitypes.Process{},
			shimPID:      100,
			expectedTree: map[uint32]apitypes.Process{},
			description:  "Should handle empty process tree gracefully",
		},
		{
			name: "orphaned_processes",
			initialTree: map[uint32]apitypes.Process{
				100: {PID: 100, PPID: 1, Comm: "shim", Children: []apitypes.Process{}},     // shim process
				200: {PID: 200, PPID: 100, Comm: "parent", Children: []apitypes.Process{}}, // direct child of shim
				201: {PID: 201, PPID: 999, Comm: "orphan", Children: []apitypes.Process{}}, // orphaned process (parent doesn't exist)
			},
			shimPID: 100,
			expectedTree: map[uint32]apitypes.Process{
				100: {PID: 100, PPID: 1, Comm: "shim", Children: []apitypes.Process{}},     // shim remains
				201: {PID: 201, PPID: 999, Comm: "orphan", Children: []apitypes.Process{}}, // orphan unaffected
			},
			description: "Should handle orphaned processes correctly",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create process manager with test data
			pm := &ProcessManager{}

			// Populate initial process tree
			for pid, process := range tc.initialTree {
				pm.processTree.Set(pid, process)
			}

			// Call the function under test
			pm.removeProcessesUnderShim(tc.shimPID)

			// Verify results
			assert.Equal(t, len(tc.expectedTree), len(pm.processTree.Keys()),
				"Process tree size mismatch after removal")

			// Check each expected process
			for pid, expectedProcess := range tc.expectedTree {
				actualProcess, exists := pm.processTree.Load(pid)
				assert.True(t, exists, "Expected process %d not found in tree", pid)
				assert.Equal(t, expectedProcess, actualProcess,
					"Process %d details don't match expected values", pid)
			}

			// Verify no unexpected processes remain
			pm.processTree.Range(func(pid uint32, process apitypes.Process) bool {
				_, shouldExist := tc.expectedTree[pid]
				assert.True(t, shouldExist,
					"Unexpected process %d found in tree", pid)
				return true
			})
		})
	}
}

func TestIsDescendantOfShim(t *testing.T) {
	tests := []struct {
		name        string
		processes   map[uint32]apitypes.Process
		shimPIDs    map[uint32]struct{}
		pid         uint32
		ppid        uint32
		expected    bool
		description string
	}{
		{
			name: "direct_child_of_shim",
			processes: map[uint32]apitypes.Process{
				100: {PID: 100, PPID: 1, Comm: "shim"},
				200: {PID: 200, PPID: 100, Comm: "child"},
			},
			shimPIDs: map[uint32]struct{}{
				100: {},
			},
			pid:         200,
			ppid:        100,
			expected:    true,
			description: "Process is a direct child of shim",
		},
		{
			name: "indirect_descendant",
			processes: map[uint32]apitypes.Process{
				100: {PID: 100, PPID: 1, Comm: "shim"},
				200: {PID: 200, PPID: 100, Comm: "parent"},
				300: {PID: 300, PPID: 200, Comm: "child"},
			},
			shimPIDs: map[uint32]struct{}{
				100: {},
			},
			pid:         300,
			ppid:        200,
			expected:    true,
			description: "Process is an indirect descendant of shim",
		},
		{
			name: "not_a_descendant",
			processes: map[uint32]apitypes.Process{
				100: {PID: 100, PPID: 1, Comm: "shim"},
				200: {PID: 200, PPID: 2, Comm: "unrelated"},
			},
			shimPIDs: map[uint32]struct{}{
				100: {},
			},
			pid:         200,
			ppid:        2,
			expected:    false,
			description: "Process is not a descendant of any shim",
		},
		{
			name: "circular_reference",
			processes: map[uint32]apitypes.Process{
				100: {PID: 100, PPID: 1, Comm: "shim"},
				200: {PID: 200, PPID: 300, Comm: "circular1"},
				300: {PID: 300, PPID: 200, Comm: "circular2"},
			},
			shimPIDs: map[uint32]struct{}{
				100: {},
			},
			pid:         200,
			ppid:        300,
			expected:    false,
			description: "Process is part of a circular reference",
		},
		{
			name: "process_chain_exceeds_max_depth",
			processes: func() map[uint32]apitypes.Process {
				// Create a chain where the target process is maxTreeDepth + 1 steps away from any shim
				procs := map[uint32]apitypes.Process{
					1: {PID: 1, PPID: 0, Comm: "init"}, // init process
					2: {PID: 2, PPID: 1, Comm: "shim"}, // shim process
				}
				// Create a chain starting far from the shim
				currentPPID := uint32(100) // Start with a different base to avoid conflicts
				targetPID := uint32(100 + maxTreeDepth + 1)

				// Build the chain backwards from target to base
				for pid := targetPID; pid > currentPPID; pid-- {
					procs[pid] = apitypes.Process{
						PID:  pid,
						PPID: pid - 1,
						Comm: fmt.Sprintf("process-%d", pid),
					}
				}
				// Add the base process that's not connected to shim
				procs[currentPPID] = apitypes.Process{
					PID:  currentPPID,
					PPID: currentPPID - 1,
					Comm: fmt.Sprintf("process-%d", currentPPID),
				}
				return procs
			}(),
			shimPIDs: map[uint32]struct{}{
				2: {}, // Shim PID
			},
			pid:         uint32(100 + maxTreeDepth + 1), // Target process at the end of chain
			ppid:        uint32(100 + maxTreeDepth),     // Its immediate parent
			expected:    false,
			description: "Process chain exceeds maximum allowed depth",
		},
		{
			name: "multiple_shims",
			processes: map[uint32]apitypes.Process{
				100: {PID: 100, PPID: 1, Comm: "shim1"},
				101: {PID: 101, PPID: 1, Comm: "shim2"},
				200: {PID: 200, PPID: 100, Comm: "child1"},
				201: {PID: 201, PPID: 101, Comm: "child2"},
			},
			shimPIDs: map[uint32]struct{}{
				100: {},
				101: {},
			},
			pid:         200,
			ppid:        100,
			expected:    true,
			description: "Multiple shims in the system",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pm := &ProcessManager{}
			result := pm.isDescendantOfShim(tc.pid, tc.ppid, tc.shimPIDs, tc.processes)
			assert.Equal(t, tc.expected, result, tc.description)
		})
	}
}
