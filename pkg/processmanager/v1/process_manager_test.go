package processmanager

import (
	"context"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

// mockProcessInfo helps simulate process information for testing
type mockProcessInfo struct {
	pid     uint32
	ppid    uint32
	comm    string
	cmdline string
}

func TestProcessManagerBasics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := CreateProcessManager(ctx)
	require.NotNil(t, pm)

	// Test container creation
	containerID := "test-container-1"
	shimPID := uint32(1000)

	// Simulate container creation
	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID: containerID,
				},
			},
			Pid: shimPID,
		},
	})

	// Verify shim PID was recorded
	assert.True(t, pm.containerIdToShimPid.Has(containerID))
	assert.Equal(t, shimPID, pm.containerIdToShimPid.Get(containerID))
}

func TestProcessTracking(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := CreateProcessManager(ctx)
	containerID := "test-container-1"
	shimPID := uint32(1000)

	// Simulate container creation
	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID: containerID,
				},
			},
			Pid: shimPID,
		},
	})

	// Simulate process creation events
	testCases := []struct {
		name   string
		event  tracerexectype.Event
		verify func(t *testing.T, pm *ProcessManager)
	}{
		{
			name: "Direct child of shim",
			event: tracerexectype.Event{
				Pid:  1001,
				Ppid: shimPID,
				Comm: "nginx",
				Args: []string{"nginx", "-g", "daemon off;"},
			},
			verify: func(t *testing.T, pm *ProcessManager) {
				proc, exists := pm.processTree.Load(1001)
				require.True(t, exists)
				assert.Equal(t, uint32(1001), proc.PID)
				assert.Equal(t, shimPID, proc.PPID)
				assert.Equal(t, "nginx", proc.Comm)
			},
		},
		{
			name: "Child of nginx",
			event: tracerexectype.Event{
				Pid:  1002,
				Ppid: 1001,
				Comm: "nginx-worker",
				Args: []string{"nginx", "worker process"},
			},
			verify: func(t *testing.T, pm *ProcessManager) {
				proc, exists := pm.processTree.Load(1002)
				require.True(t, exists)
				assert.Equal(t, uint32(1002), proc.PID)
				assert.Equal(t, uint32(1001), proc.PPID)

				// Verify parent's children list
				parent, exists := pm.processTree.Load(1001)
				require.True(t, exists)
				found := false
				for _, child := range parent.Children {
					if child.PID == 1002 {
						found = true
						break
					}
				}
				assert.True(t, found, "Child process should be in parent's children list")
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

func TestProcessCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := CreateProcessManager(ctx)
	containerID := "test-container-1"
	shimPID := uint32(1000)

	// Simulate container creation
	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID: containerID,
				},
			},
			Pid: shimPID,
		},
	})

	// Add some test processes
	processes := []mockProcessInfo{
		{pid: 1001, ppid: shimPID, comm: "parent", cmdline: "./parent"},
		{pid: 1002, ppid: 1001, comm: "child1", cmdline: "./child1"},
		{pid: 1003, ppid: 1001, comm: "child2", cmdline: "./child2"},
	}

	for _, proc := range processes {
		event := tracerexectype.Event{
			Pid:  proc.pid,
			Ppid: proc.ppid,
			Comm: proc.comm,
			Args: []string{proc.cmdline},
		}
		pm.ReportEvent(utils.ExecveEventType, &event)
	}

	// Verify initial state
	for _, proc := range processes {
		assert.True(t, pm.processTree.Has(proc.pid))
	}

	// Simulate container removal
	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeRemoveContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID: containerID,
				},
			},
			Pid: shimPID,
		},
	})

	// Verify cleanup
	for _, proc := range processes {
		assert.False(t, pm.processTree.Has(proc.pid),
			"Process %d should be removed after container cleanup", proc.pid)
	}
	assert.False(t, pm.containerIdToShimPid.Has(containerID))
}

func TestGetProcessTree(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := CreateProcessManager(ctx)
	containerID := "test-container-1"
	shimPID := uint32(1000)

	// Setup container
	pm.ContainerCallback(containercollection.PubSubEvent{
		Type: containercollection.EventTypeAddContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID: containerID,
				},
			},
			Pid: shimPID,
		},
	})

	// Create a process tree:
	// shim (1000)
	// └── parent (1001)
	//     ├── child1 (1002)
	//     └── child2 (1003)
	//         └── grandchild (1004)

	processes := []mockProcessInfo{
		{pid: 1001, ppid: shimPID, comm: "parent", cmdline: "./parent"},
		{pid: 1002, ppid: 1001, comm: "child1", cmdline: "./child1"},
		{pid: 1003, ppid: 1001, comm: "child2", cmdline: "./child2"},
		{pid: 1004, ppid: 1003, comm: "grandchild", cmdline: "./grandchild"},
	}

	// Add processes to tree
	for _, proc := range processes {
		event := &tracerexectype.Event{
			Pid:  proc.pid,
			Ppid: proc.ppid,
			Comm: proc.comm,
			Args: []string{proc.cmdline},
		}
		pm.ReportEvent(utils.ExecveEventType, event)
	}

	// Get and verify process tree for grandchild
	tree, err := pm.GetProcessTreeForPID(containerID, 1004)
	require.NoError(t, err)

	// Helper function to find a process in the tree
	var findProcess func(apitypes.Process, uint32) *apitypes.Process
	findProcess = func(node apitypes.Process, targetPID uint32) *apitypes.Process {
		if node.PID == targetPID {
			return &node
		}
		for _, child := range node.Children {
			if found := findProcess(child, targetPID); found != nil {
				return found
			}
		}
		return nil
	}

	// Verify tree structure
	t.Run("verify tree structure", func(t *testing.T) {
		// Check the chain from grandchild up to parent
		current := &tree
		expectedChain := []uint32{1001, 1003, 1004} // parent -> child2 -> grandchild

		for i, expectedPID := range expectedChain {
			assert.Equal(t, expectedPID, current.PID, "Mismatch at chain position %d", i)
			if i < len(expectedChain)-1 {
				require.Len(t, current.Children, 1, "Expected exactly one child at position %d", i)
				current = &current.Children[0]
			}
		}
	})

	// Verify process details
	t.Run("verify process details", func(t *testing.T) {
		for _, expected := range processes {
			proc := findProcess(tree, expected.pid)
			if proc != nil {
				assert.Equal(t, expected.ppid, proc.PPID)
				assert.Equal(t, expected.comm, proc.Comm)
				assert.Equal(t, expected.cmdline, proc.Cmdline)
			}
		}
	})
}

func TestContainerLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := CreateProcessManager(ctx)

	containers := []struct {
		id      string
		shimPID uint32
	}{
		{"container-1", 1000},
		{"container-2", 2000},
	}

	// Add containers
	for _, c := range containers {
		pm.ContainerCallback(containercollection.PubSubEvent{
			Type: containercollection.EventTypeAddContainer,
			Container: &containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerID: c.id,
					},
				},
				Pid: c.shimPID,
			},
		})
	}

	// Verify containers were added
	for _, c := range containers {
		assert.True(t, pm.containerIdToShimPid.Has(c.id))
		assert.Equal(t, c.shimPID, pm.containerIdToShimPid.Get(c.id))
	}

	// Remove containers
	for _, c := range containers {
		pm.ContainerCallback(containercollection.PubSubEvent{
			Type: containercollection.EventTypeRemoveContainer,
			Container: &containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerID: c.id,
					},
				},
				Pid: c.shimPID,
			},
		})

		// Verify container was removed
		assert.False(t, pm.containerIdToShimPid.Has(c.id))
	}
}

func TestCleanupRoutine(t *testing.T) {
	// This is a bit tricky to test since we can't easily simulate dead processes
	// But we can test that the cleanup routine runs without errors
	ctx, cancel := context.WithCancel(context.Background())
	CreateProcessManager(ctx)

	// Let it run for a short while
	time.Sleep(2 * time.Second)

	// Cancel and ensure it shuts down cleanly
	cancel()
	time.Sleep(100 * time.Millisecond)
}
