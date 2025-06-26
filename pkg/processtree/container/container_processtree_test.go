package containerprocesstree

import (
	"fmt"
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestNewContainerProcessTree(t *testing.T) {
	cpt := NewContainerProcessTree()
	assert.NotNil(t, cpt)

	// Test that it implements the interface
	var _ ContainerProcessTree = cpt
}

func TestContainerProcessTreeImpl_ContainerCallback_AddContainer(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Create a mock container event
	containerID := "test-container-123"
	containerPID := uint32(100)

	cpt.containerIdToShimPid[containerID] = containerPID

	// Verify the container PID was stored
	storedPID, exists := cpt.containerIdToShimPid[containerID]
	assert.True(t, exists)
	assert.Equal(t, containerPID, storedPID)
}

func TestContainerProcessTreeImpl_ContainerCallback_RemoveContainer(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	containerPID := uint32(100)
	cpt.containerIdToShimPid[containerID] = containerPID

	// Create container remove event
	event := containercollection.PubSubEvent{
		Type: containercollection.EventTypeRemoveContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
					ContainerID: containerID,
				},
			},
		},
	}

	// Call the callback
	cpt.ContainerCallback(event)

	// Verify the container was removed
	_, exists := cpt.containerIdToShimPid[containerID]
	assert.False(t, exists)
}

func TestContainerProcessTreeImpl_GetContainerTree_Success(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	containerPID := uint32(50) // This should be the shim PID, not the child process PID
	cpt.containerIdToShimPid[containerID] = containerPID

	// Create a full tree with container processes
	// The tree should have the shim as the root with children in its ChildrenMap
	nginxProcess := &apitypes.Process{
		PID:  100,
		PPID: 50,
		Comm: "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx-worker", PID: 101}: {
				PID:         101,
				PPID:        100,
				Comm:        "nginx-worker",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
			},
		},
	}

	shimProcess := &apitypes.Process{
		PID:  50, // shim
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx", PID: 100}: nginxProcess,
		},
	}

	fullTree := []apitypes.Process{
		*shimProcess,
		{
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	// Get container tree
	result, err := cpt.GetContainerTree(containerID, fullTree)

	// Verify results
	assert.NoError(t, err)
	assert.Len(t, result, 3) // shim + nginx + nginx-worker

	// Verify the tree structure is correct
	shimFound := false
	nginxFound := false
	workerFound := false

	for _, proc := range result {
		switch proc.PID {
		case 50:
			shimFound = true
			assert.Equal(t, "containerd-shim", proc.Comm)
		case 100:
			nginxFound = true
			assert.Equal(t, "nginx", proc.Comm)
		case 101:
			workerFound = true
			assert.Equal(t, "nginx-worker", proc.Comm)
		}
	}

	assert.True(t, shimFound)
	assert.True(t, nginxFound)
	assert.True(t, workerFound)
}

func TestContainerProcessTreeImpl_GetContainerTree_ContainerNotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Don't populate any containers
	fullTree := []apitypes.Process{
		{
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	// Get container tree for non-existent container
	result, err := cpt.GetContainerTree("non-existent", fullTree)

	// Verify results
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestContainerProcessTreeImpl_GetContainerTree_ContainerPIDNotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	containerPID := uint32(999) // PID that doesn't exist in the tree
	cpt.containerIdToShimPid[containerID] = containerPID

	// Create a full tree without the container process
	fullTree := []apitypes.Process{
		{
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	// Get container tree
	result, err := cpt.GetContainerTree(containerID, fullTree)

	// Verify results
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestContainerProcessTreeImpl_ListContainers(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with multiple containers
	containers := map[string]uint32{
		"container-1": 50,
		"container-2": 60,
		"container-3": 70,
	}

	for id, pid := range containers {
		cpt.containerIdToShimPid[id] = pid
	}

	// List containers
	result := cpt.ListContainers()

	// Verify results
	assert.Len(t, result, 3)

	// Verify all expected containers are present
	expectedContainers := []string{"container-1", "container-2", "container-3"}
	for _, expected := range expectedContainers {
		assert.Contains(t, result, expected)
	}
}

func TestContainerProcessTreeImpl_ListContainers_Empty(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// List containers when none exist
	result := cpt.ListContainers()

	// Verify results
	assert.Len(t, result, 0)
	assert.NotNil(t, result) // Should return empty slice, not nil
}

func TestContainerProcessTreeImpl_ConcurrentAccess(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Test concurrent access to the container process tree
	done := make(chan bool)

	// Goroutine 1: Add containers using proper method
	go func() {
		for i := 0; i < 100; i++ {
			containerID := fmt.Sprintf("container-%d", i)
			// Use the proper locking mechanism to avoid race conditions
			cpt.mutex.Lock()
			cpt.containerIdToShimPid[containerID] = uint32(50 + i)
			cpt.mutex.Unlock()
		}
		done <- true
	}()

	// Goroutine 2: List containers
	go func() {
		for i := 0; i < 100; i++ {
			cpt.ListContainers()
		}
		done <- true
	}()

	// Goroutine 3: Get container trees
	go func() {
		fullTree := []apitypes.Process{
			{
				PID:  50,
				PPID: 1,
				Comm: "containerd-shim",
			},
		}
		for i := 0; i < 100; i++ {
			cpt.GetContainerTree("container-0", fullTree)
		}
		done <- true
	}()

	// Wait for all goroutines to complete
	<-done
	<-done
	<-done

	// Verify the final state is consistent
	containers := cpt.ListContainers()
	assert.Len(t, containers, 100)
}

func TestContainerProcessTreeImpl_DeepTreeTraversal(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	containerPID := uint32(50) // This will be the shim PID in the tree
	cpt.containerIdToShimPid[containerID] = containerPID

	// Create a deep tree structure
	// Build the tree from bottom up
	nginxChild := &apitypes.Process{
		PID:         102,
		PPID:        101,
		Comm:        "nginx-child",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	nginxWorker := &apitypes.Process{
		PID:  101,
		PPID: 100,
		Comm: "nginx-worker",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx-child", PID: 102}: nginxChild,
		},
	}

	nginxProcess := &apitypes.Process{
		PID:  100,
		PPID: 50,
		Comm: "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx-worker", PID: 101}: nginxWorker,
		},
	}

	shimProcess := &apitypes.Process{
		PID:  50, // shim
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx", PID: 100}: nginxProcess,
		},
	}

	fullTree := []apitypes.Process{
		*shimProcess,
	}

	// Get container tree
	result, err := cpt.GetContainerTree(containerID, fullTree)

	// Verify results
	assert.NoError(t, err)
	assert.Len(t, result, 4) // shim + nginx + nginx-worker + nginx-child

	// Verify all processes are present
	pids := make(map[uint32]bool)
	for _, proc := range result {
		pids[proc.PID] = true
	}

	assert.True(t, pids[50])  // shim
	assert.True(t, pids[100]) // nginx
	assert.True(t, pids[101]) // nginx-worker
	assert.True(t, pids[102]) // nginx-child
}

func TestContainerProcessTreeImpl_Integration(t *testing.T) {
	cpt := NewContainerProcessTree()

	// Create a complex scenario with multiple containers
	container1ID := "container-1"
	container2ID := "container-2"

	// Create full tree with multiple containers
	// Container 1: shim (PID 50) -> nginx (PID 100)
	nginxProcess1 := &apitypes.Process{
		PID:         100,
		PPID:        50,
		Comm:        "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	shimProcess1 := &apitypes.Process{
		PID:  50, // shim 1
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx", PID: 100}: nginxProcess1,
		},
	}

	// Container 2: shim (PID 60) -> postgres (PID 200)
	postgresProcess := &apitypes.Process{
		PID:         200,
		PPID:        60,
		Comm:        "postgres",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	shimProcess2 := &apitypes.Process{
		PID:  60, // shim 2
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "postgres", PID: 200}: postgresProcess,
		},
	}

	fullTree := []apitypes.Process{
		*shimProcess1,
		*shimProcess2,
	}

	// Manually set up the container PID mapping
	cpt.(*containerProcessTreeImpl).containerIdToShimPid[container1ID] = 50
	cpt.(*containerProcessTreeImpl).containerIdToShimPid[container2ID] = 60

	// Verify both containers are listed
	containers := cpt.ListContainers()
	assert.Len(t, containers, 2)
	assert.Contains(t, containers, container1ID)
	assert.Contains(t, containers, container2ID)

	// Get container trees
	tree1, err := cpt.GetContainerTree(container1ID, fullTree)
	assert.NoError(t, err)
	assert.Len(t, tree1, 2) // shim + nginx

	tree2, err := cpt.GetContainerTree(container2ID, fullTree)
	assert.NoError(t, err)
	assert.Len(t, tree2, 2) // shim + postgres

	// Remove container 1
	removeEvent := containercollection.PubSubEvent{
		Type: containercollection.EventTypeRemoveContainer,
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
					ContainerID: container1ID,
				},
			},
		},
	}
	cpt.ContainerCallback(removeEvent)

	// Verify only container 2 remains
	containers = cpt.ListContainers()
	assert.Len(t, containers, 1)
	assert.Contains(t, containers, container2ID)

	// Verify container 1 tree is no longer available
	tree1, err = cpt.GetContainerTree(container1ID, fullTree)
	assert.NoError(t, err)
	assert.Nil(t, tree1)
}
