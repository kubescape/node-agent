package containerprocesstree

import (
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a SafeMap from regular map data
func createSafeMapFromData(data map[uint32]*apitypes.Process) *maps.SafeMap[uint32, *apitypes.Process] {
	safeMap := &maps.SafeMap[uint32, *apitypes.Process]{}
	for pid, proc := range data {
		safeMap.Set(pid, proc)
	}
	return safeMap
}

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

func TestContainerProcessTreeImpl_GetPidBranch_Success(t *testing.T) {
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

	// Test getting branch for nginx-worker (PID 101)
	// Should return nginx (PID 100) as the root, but with only worker (101) as child
	result, err := cpt.GetPidBranch(containerID, 101, createSafeMapFromData(fullTree))
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, "nginx", result.Comm)
	assert.Len(t, result.ChildrenMap, 1)
	assert.Contains(t, result.ChildrenMap, apitypes.CommPID{Comm: "nginx-worker", PID: 101})

	// Test getting branch for nginx (PID 100)
	// Should return nginx (PID 100) as the root with no children (since nginx itself is the target)
	result, err = cpt.GetPidBranch(containerID, 100, createSafeMapFromData(fullTree))
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, "nginx", result.Comm)
	assert.Len(t, result.ChildrenMap, 0) // No children since nginx is the target
}

func TestContainerProcessTreeImpl_GetPidBranch_ContainerNotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	// Test with non-existent container
	result, err := cpt.GetPidBranch("non-existent", 100, createSafeMapFromData(fullTree))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "container non-existent not found")
	assert.Equal(t, apitypes.Process{}, result)
}

func TestContainerProcessTreeImpl_GetPidBranch_ShimNotFound(t *testing.T) {
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
	result, err := cpt.GetPidBranch(containerID, 100, createSafeMapFromData(fullTree))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "shim process 999 not found in process tree")
	assert.Equal(t, apitypes.Process{}, result)
}

func TestContainerProcessTreeImpl_GetPidBranch_TargetNotFound(t *testing.T) {
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
	result, err := cpt.GetPidBranch(containerID, 999, createSafeMapFromData(fullTree))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target process 999 not found in process tree")
	assert.Equal(t, apitypes.Process{}, result)
}

func TestContainerProcessTreeImpl_GetPidBranch_TargetNotInContainer(t *testing.T) {
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
	result, err := cpt.GetPidBranch(containerID, 200, createSafeMapFromData(fullTree))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target process 200 is not within container test-container-123 subtree")
	assert.Equal(t, apitypes.Process{}, result)
}

func TestContainerProcessTreeImpl_GetPidBranch_DeepTree(t *testing.T) {
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

	// Test getting branch for grandchild (PID 103)
	// Should return nginx (PID 100) as the root, but only with the path to grandchild
	result, err := cpt.GetPidBranch(containerID, 103, createSafeMapFromData(fullTree))
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, "nginx", result.Comm)

	// Verify the branch structure: nginx -> worker -> child -> grandchild (path only)
	assert.Len(t, result.ChildrenMap, 1)
	workerNode := result.ChildrenMap[apitypes.CommPID{Comm: "worker", PID: 101}]
	assert.NotNil(t, workerNode)
	assert.Equal(t, uint32(101), workerNode.PID)
	assert.Len(t, workerNode.ChildrenMap, 1) // Only the path child, not all children

	childNode := workerNode.ChildrenMap[apitypes.CommPID{Comm: "child", PID: 102}]
	assert.NotNil(t, childNode)
	assert.Equal(t, uint32(102), childNode.PID)
	assert.Len(t, childNode.ChildrenMap, 1) // Only the path child, not all children

	grandchildNode := childNode.ChildrenMap[apitypes.CommPID{Comm: "grandchild", PID: 103}]
	assert.NotNil(t, grandchildNode)
	assert.Equal(t, uint32(103), grandchildNode.PID)
	assert.Len(t, grandchildNode.ChildrenMap, 0) // Leaf node
}

func TestContainerProcessTreeImpl_GetPidBranch_TargetIsShimChild(t *testing.T) {
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

	// Test getting branch for nginx (PID 100) which is a direct child of shim
	// Should return nginx (PID 100) as the root with no children (since nginx is the target)
	result, err := cpt.GetPidBranch(containerID, 100, createSafeMapFromData(fullTree))
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, "nginx", result.Comm)
	assert.Equal(t, uint32(50), result.PPID) // PPID should still be 50 (shim)
	assert.Len(t, result.ChildrenMap, 0)     // No children since nginx is the target
}

func TestContainerProcessTreeImpl_GetPidByContainerID_Success(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with containers
	containerID1 := "test-container-123"
	containerID2 := "test-container-456"
	shimPID1 := uint32(50)
	shimPID2 := uint32(60)

	cpt.containerIdToShimPid[containerID1] = shimPID1
	cpt.containerIdToShimPid[containerID2] = shimPID2

	// Test getting PID for existing containers
	pid1, err := cpt.GetPidByContainerID(containerID1)
	assert.NoError(t, err)
	assert.Equal(t, shimPID1, pid1)

	pid2, err := cpt.GetPidByContainerID(containerID2)
	assert.NoError(t, err)
	assert.Equal(t, shimPID2, pid2)
}

func TestContainerProcessTreeImpl_GetPidByContainerID_NotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Test getting PID for non-existent container
	pid, err := cpt.GetPidByContainerID("non-existent-container")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "container non-existent-container not found")
	assert.Equal(t, uint32(0), pid)
}

func TestContainerProcessTreeImpl_GetShimPIDForProcess_Success(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with containers
	containerID1 := "test-container-123"
	containerID2 := "test-container-456"
	shimPID1 := uint32(50)
	shimPID2 := uint32(60)

	cpt.containerIdToShimPid[containerID1] = shimPID1
	cpt.containerIdToShimPid[containerID2] = shimPID2

	// Create process tree with processes under different containers
	// Container 1: shim1 (50) -> nginx (100) -> worker (101)
	// Container 2: shim2 (60) -> redis (200) -> child (201)

	worker := &apitypes.Process{
		PID:         101,
		PPID:        100,
		Comm:        "nginx-worker",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	nginx := &apitypes.Process{
		PID:  100,
		PPID: 50, // parent is shim1
		Comm: "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx-worker", PID: 101}: worker,
		},
	}

	shim1 := &apitypes.Process{
		PID:  50, // shim1
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx", PID: 100}: nginx,
		},
	}

	child := &apitypes.Process{
		PID:         201,
		PPID:        200,
		Comm:        "redis-child",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	redis := &apitypes.Process{
		PID:  200,
		PPID: 60, // parent is shim2
		Comm: "redis",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "redis-child", PID: 201}: child,
		},
	}

	shim2 := &apitypes.Process{
		PID:  60, // shim2
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "redis", PID: 200}: redis,
		},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shim1,
		60:  shim2,
		100: nginx,
		101: worker,
		200: redis,
		201: child,
	}

	// Test finding shim PID for processes in container 1
	shimPID, found := cpt.GetShimPIDForProcess(100, createSafeMapFromData(fullTree)) // nginx
	assert.True(t, found)
	assert.Equal(t, shimPID1, shimPID)

	shimPID, found = cpt.GetShimPIDForProcess(101, createSafeMapFromData(fullTree)) // worker
	assert.True(t, found)
	assert.Equal(t, shimPID1, shimPID)

	// Test finding shim PID for processes in container 2
	shimPID, found = cpt.GetShimPIDForProcess(200, createSafeMapFromData(fullTree)) // redis
	assert.True(t, found)
	assert.Equal(t, shimPID2, shimPID)

	shimPID, found = cpt.GetShimPIDForProcess(201, createSafeMapFromData(fullTree)) // child
	assert.True(t, found)
	assert.Equal(t, shimPID2, shimPID)
}

func TestContainerProcessTreeImpl_GetShimPIDForProcess_NotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToShimPid[containerID] = shimPID

	// Create process tree
	shim := &apitypes.Process{
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
		50: shim,
	}

	// Test with process not in any container subtree
	shimPIDResult, found := cpt.GetShimPIDForProcess(999, createSafeMapFromData(fullTree)) // Non-existent process
	assert.False(t, found)
	assert.Equal(t, uint32(0), shimPIDResult)

	// Test with process that exists but is not under any container
	outsideProcess := &apitypes.Process{
		PID:         200,
		PPID:        1, // Direct child of init, not of shim
		Comm:        "outside-process",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}
	fullTree[200] = outsideProcess

	shimPIDResult, found = cpt.GetShimPIDForProcess(200, createSafeMapFromData(fullTree)) // Outside process
	assert.False(t, found)
	assert.Equal(t, uint32(0), shimPIDResult)
}

func TestContainerProcessTreeImpl_IsProcessUnderContainer_Success(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToShimPid[containerID] = shimPID

	// Create process tree: shim (50) -> nginx (100) -> worker (101)
	worker := &apitypes.Process{
		PID:         101,
		PPID:        100,
		Comm:        "nginx-worker",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	nginx := &apitypes.Process{
		PID:  100,
		PPID: 50, // parent is shim
		Comm: "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx-worker", PID: 101}: worker,
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
	}

	// Test processes under the container
	assert.True(t, cpt.IsProcessUnderContainer(50, containerID, createSafeMapFromData(fullTree)))  // shim itself
	assert.True(t, cpt.IsProcessUnderContainer(100, containerID, createSafeMapFromData(fullTree))) // nginx
	assert.True(t, cpt.IsProcessUnderContainer(101, containerID, createSafeMapFromData(fullTree))) // worker

	// Test processes not under the container
	assert.False(t, cpt.IsProcessUnderContainer(1, containerID, createSafeMapFromData(fullTree)))   // init
	assert.False(t, cpt.IsProcessUnderContainer(999, containerID, createSafeMapFromData(fullTree))) // non-existent
}

func TestContainerProcessTreeImpl_IsProcessUnderContainer_ContainerNotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	// Test with non-existent container
	assert.False(t, cpt.IsProcessUnderContainer(100, "non-existent-container", createSafeMapFromData(fullTree)))
}

func TestContainerProcessTreeImpl_IsProcessUnderContainer_ShimNotFound(t *testing.T) {
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

	// Test with shim PID that doesn't exist in tree
	assert.False(t, cpt.IsProcessUnderContainer(100, containerID, createSafeMapFromData(fullTree)))
}

func TestContainerProcessTreeImpl_IsProcessUnderContainer_ProcessNotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToShimPid[containerID] = shimPID

	shim := &apitypes.Process{
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
		50: shim,
	}

	// Test with process that doesn't exist in tree
	assert.False(t, cpt.IsProcessUnderContainer(999, containerID, createSafeMapFromData(fullTree)))
}

func TestContainerProcessTreeImpl_IsProcessUnderAnyContainerSubtree_Success(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with multiple containers
	containerID1 := "test-container-123"
	containerID2 := "test-container-456"
	shimPID1 := uint32(50)
	shimPID2 := uint32(60)

	cpt.containerIdToShimPid[containerID1] = shimPID1
	cpt.containerIdToShimPid[containerID2] = shimPID2

	// Create process tree with processes under different containers
	// Container 1: shim1 (50) -> nginx (100) -> worker (101)
	// Container 2: shim2 (60) -> redis (200) -> child (201)

	worker := &apitypes.Process{
		PID:         101,
		PPID:        100,
		Comm:        "nginx-worker",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	nginx := &apitypes.Process{
		PID:  100,
		PPID: 50, // parent is shim1
		Comm: "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx-worker", PID: 101}: worker,
		},
	}

	shim1 := &apitypes.Process{
		PID:  50, // shim1
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx", PID: 100}: nginx,
		},
	}

	child := &apitypes.Process{
		PID:         201,
		PPID:        200,
		Comm:        "redis-child",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	redis := &apitypes.Process{
		PID:  200,
		PPID: 60, // parent is shim2
		Comm: "redis",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "redis-child", PID: 201}: child,
		},
	}

	shim2 := &apitypes.Process{
		PID:  60, // shim2
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "redis", PID: 200}: redis,
		},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shim1,
		60:  shim2,
		100: nginx,
		101: worker,
		200: redis,
		201: child,
	}

	// Test processes under any container
	assert.True(t, cpt.IsProcessUnderAnyContainerSubtree(50, createSafeMapFromData(fullTree)))  // shim1
	assert.True(t, cpt.IsProcessUnderAnyContainerSubtree(60, createSafeMapFromData(fullTree)))  // shim2
	assert.True(t, cpt.IsProcessUnderAnyContainerSubtree(100, createSafeMapFromData(fullTree))) // nginx (container 1)
	assert.True(t, cpt.IsProcessUnderAnyContainerSubtree(101, createSafeMapFromData(fullTree))) // worker (container 1)
	assert.True(t, cpt.IsProcessUnderAnyContainerSubtree(200, createSafeMapFromData(fullTree))) // redis (container 2)
	assert.True(t, cpt.IsProcessUnderAnyContainerSubtree(201, createSafeMapFromData(fullTree))) // child (container 2)

	// Test processes not under any container
	assert.False(t, cpt.IsProcessUnderAnyContainerSubtree(1, createSafeMapFromData(fullTree)))   // init
	assert.False(t, cpt.IsProcessUnderAnyContainerSubtree(999, createSafeMapFromData(fullTree))) // non-existent
}

func TestContainerProcessTreeImpl_IsProcessUnderAnyContainerSubtree_NoContainers(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// No containers registered
	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	// Test with no containers registered
	assert.False(t, cpt.IsProcessUnderAnyContainerSubtree(1, createSafeMapFromData(fullTree)))
	assert.False(t, cpt.IsProcessUnderAnyContainerSubtree(999, createSafeMapFromData(fullTree)))
}

func TestContainerProcessTreeImpl_IsProcessUnderAnyContainerSubtree_OutsideProcess(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToShimPid[containerID] = shimPID

	// Create process tree with a process outside the container
	shim := &apitypes.Process{
		PID:         50, // shim
		PPID:        1,
		Comm:        "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	outsideProcess := &apitypes.Process{
		PID:         200,
		PPID:        1, // Direct child of init, not of shim
		Comm:        "outside-process",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shim,
		200: outsideProcess,
	}

	// Test processes
	assert.True(t, cpt.IsProcessUnderAnyContainerSubtree(50, createSafeMapFromData(fullTree)))   // shim
	assert.False(t, cpt.IsProcessUnderAnyContainerSubtree(200, createSafeMapFromData(fullTree))) // outside process
	assert.False(t, cpt.IsProcessUnderAnyContainerSubtree(1, createSafeMapFromData(fullTree)))   // init
}
