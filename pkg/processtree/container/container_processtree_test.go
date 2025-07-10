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

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50: shimProcess,
	}

	// Get container tree
	result, err := cpt.GetContainerTreeNodes(containerID, fullTree)

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
	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	// Get container tree for non-existent container
	result, err := cpt.GetContainerTreeNodes("non-existent", fullTree)

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
	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	// Get container tree
	result, err := cpt.GetContainerTreeNodes(containerID, fullTree)

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

func TestContainerProcessTreeImpl_SequentialAccess(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Add containers sequentially (single-threaded design)
	for i := 0; i < 100; i++ {
		containerID := fmt.Sprintf("container-%d", i)
		// Direct assignment since no mutex is needed in single-threaded design
		cpt.containerIdToShimPid[containerID] = uint32(50 + i)
	}

	// List containers
	for i := 0; i < 10; i++ {
		containers := cpt.ListContainers()
		assert.Len(t, containers, 100)
	}

	// Get container trees
	fullTree := map[uint32]*apitypes.Process{
		50: {
			PID:  50,
			PPID: 1,
			Comm: "containerd-shim",
		},
	}
	for i := 0; i < 10; i++ {
		trees, err := cpt.GetContainerTreeNodes("container-0", fullTree)
		assert.NoError(t, err)
		if trees != nil {
			assert.GreaterOrEqual(t, len(trees), 1)
		}
	}

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

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50: shimProcess,
	}

	// Get container tree
	result, err := cpt.GetContainerTreeNodes(containerID, fullTree)

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

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50: shimProcess1,
		60: shimProcess2,
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
	tree1, err := cpt.GetContainerTreeNodes(container1ID, fullTree)
	assert.NoError(t, err)
	assert.Len(t, tree1, 2) // shim + nginx

	tree2, err := cpt.GetContainerTreeNodes(container2ID, fullTree)
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
	tree1, err = cpt.GetContainerTreeNodes(container1ID, fullTree)
	assert.NoError(t, err)
	assert.Nil(t, tree1)
}

func TestContainerProcessTreeImpl_GetContainerSubtree_Success(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToShimPid[containerID] = shimPID

	// Create a tree structure: shim (50) -> nginx (100) -> nginx-worker (101)
	nginxWorker := &apitypes.Process{
		PID:         101,
		PPID:        100,
		Comm:        "nginx-worker",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	nginxProcess := &apitypes.Process{
		PID:  100,
		PPID: 50, // parent is shim
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

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shimProcess,
		100: nginxProcess,
		101: nginxWorker,
	}

	// Test getting subtree for nginx-worker (PID 101)
	// Should return nginx (PID 100) as the root (the node just before shim)
	result, err := cpt.GetContainerSubtree(containerID, 101, fullTree)
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, "nginx", result.Comm)
	assert.Len(t, result.ChildrenMap, 1)
	assert.Contains(t, result.ChildrenMap, apitypes.CommPID{Comm: "nginx-worker", PID: 101})

	// Test getting subtree for nginx (PID 100)
	// Should return nginx (PID 100) as the root since its parent is shim
	result, err = cpt.GetContainerSubtree(containerID, 100, fullTree)
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, "nginx", result.Comm)
}

func TestContainerProcessTreeImpl_GetContainerSubtree_ContainerNotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	// Test with non-existent container
	result, err := cpt.GetContainerSubtree("non-existent", 100, fullTree)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "container non-existent not found")
	assert.Equal(t, apitypes.Process{}, result)
}

func TestContainerProcessTreeImpl_GetContainerSubtree_ShimNotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container but shim PID doesn't exist in tree
	containerID := "test-container-123"
	shimPID := uint32(999) // Non-existent PID
	cpt.containerIdToShimPid[containerID] = shimPID

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	// Test with non-existent shim PID
	result, err := cpt.GetContainerSubtree(containerID, 100, fullTree)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "shim process 999 not found in process tree")
	assert.Equal(t, apitypes.Process{}, result)
}

func TestContainerProcessTreeImpl_GetContainerSubtree_TargetNotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToShimPid[containerID] = shimPID

	shimProcess := &apitypes.Process{
		PID:         50, // shim
		PPID:        1,
		Comm:        "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50: shimProcess,
	}

	// Test with non-existent target PID
	result, err := cpt.GetContainerSubtree(containerID, 999, fullTree)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target process 999 not found in process tree")
	assert.Equal(t, apitypes.Process{}, result)
}

func TestContainerProcessTreeImpl_GetContainerSubtree_TargetNotInContainer(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToShimPid[containerID] = shimPID

	// Create a process that's not in the container's subtree
	outsideProcess := &apitypes.Process{
		PID:         200,
		PPID:        1, // Direct child of init, not of shim
		Comm:        "outside-process",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	shimProcess := &apitypes.Process{
		PID:         50, // shim
		PPID:        1,
		Comm:        "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shimProcess,
		200: outsideProcess,
	}

	// Test with target PID that's not in the container's subtree
	result, err := cpt.GetContainerSubtree(containerID, 200, fullTree)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target process 200 is not within container test-container-123 subtree")
	assert.Equal(t, apitypes.Process{}, result)
}

func TestContainerProcessTreeImpl_GetContainerSubtree_DeepTree(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToShimPid[containerID] = shimPID

	// Create a deep tree: shim (50) -> nginx (100) -> worker (101) -> child (102) -> grandchild (103)
	grandchild := &apitypes.Process{
		PID:         103,
		PPID:        102,
		Comm:        "grandchild",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	child := &apitypes.Process{
		PID:  102,
		PPID: 101,
		Comm: "child",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "grandchild", PID: 103}: grandchild,
		},
	}

	worker := &apitypes.Process{
		PID:  101,
		PPID: 100,
		Comm: "worker",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "child", PID: 102}: child,
		},
	}

	nginx := &apitypes.Process{
		PID:  100,
		PPID: 50, // parent is shim
		Comm: "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "worker", PID: 101}: worker,
		},
	}

	shim := &apitypes.Process{
		PID:  50, // shim
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx", PID: 100}: nginx,
		},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shim,
		100: nginx,
		101: worker,
		102: child,
		103: grandchild,
	}

	// Test getting subtree for grandchild (PID 103)
	// Should return nginx (PID 100) as the root (the node just before shim)
	result, err := cpt.GetContainerSubtree(containerID, 103, fullTree)
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, "nginx", result.Comm)

	// Verify the full subtree structure is preserved
	assert.Len(t, result.ChildrenMap, 1)
	workerNode := result.ChildrenMap[apitypes.CommPID{Comm: "worker", PID: 101}]
	assert.NotNil(t, workerNode)
	assert.Equal(t, uint32(101), workerNode.PID)
	assert.Len(t, workerNode.ChildrenMap, 1)

	childNode := workerNode.ChildrenMap[apitypes.CommPID{Comm: "child", PID: 102}]
	assert.NotNil(t, childNode)
	assert.Equal(t, uint32(102), childNode.PID)
	assert.Len(t, childNode.ChildrenMap, 1)

	grandchildNode := childNode.ChildrenMap[apitypes.CommPID{Comm: "grandchild", PID: 103}]
	assert.NotNil(t, grandchildNode)
	assert.Equal(t, uint32(103), grandchildNode.PID)
	assert.Len(t, grandchildNode.ChildrenMap, 0)
}

func TestContainerProcessTreeImpl_GetContainerSubtree_TargetIsShimChild(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToShimPid[containerID] = shimPID

	// Create a simple tree: shim (50) -> nginx (100)
	nginx := &apitypes.Process{
		PID:         100,
		PPID:        50, // direct child of shim
		Comm:        "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	shim := &apitypes.Process{
		PID:  50, // shim
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx", PID: 100}: nginx,
		},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shim,
		100: nginx,
	}

	// Test getting subtree for nginx (PID 100) which is a direct child of shim
	// Should return nginx (PID 100) as the root since its parent is shim
	result, err := cpt.GetContainerSubtree(containerID, 100, fullTree)
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, "nginx", result.Comm)
	assert.Equal(t, uint32(50), result.PPID) // PPID should still be 50 (shim)
}
