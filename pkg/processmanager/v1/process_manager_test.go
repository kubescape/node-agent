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
					ContainerID: containerID,
				},
			},
			Pid: containerPID,
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
					ContainerID: containerID,
				},
			},
			Pid: containerPID,
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
					ContainerID: containerID,
				},
			},
			Pid: containerPID,
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
					ContainerID: containerID,
				},
			},
			Pid: containerPID,
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
					ContainerID: containerID,
				},
			},
			Pid: containerPID,
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
						ContainerID: c.id,
					},
				},
				Pid: c.containerPID,
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
					ContainerID: containers[0].id,
				},
			},
			Pid: containers[0].containerPID,
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
						ContainerID: containerID,
					},
				},
				Pid: containerPID,
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
					ContainerID: containerID,
				},
			},
			Pid: containerPID,
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
