package containerprocesstree

import (
	"testing"
	"time"

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

	// Manually register a container with shim info
	containerID := "test-container-123"
	shimPID := uint32(50)
	containerPID := uint32(100)

	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: containerPID,
		registeredAt: time.Now(),
	}

	// Verify the container info was stored
	info, exists := cpt.containerIdToInfo[containerID]
	assert.True(t, exists)
	assert.Equal(t, shimPID, info.shimPID)
	assert.Equal(t, containerPID, info.containerPID)
}

func TestContainerProcessTreeImpl_ContainerCallback_RemoveContainer(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	containerPID := uint32(100)
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: containerPID,
		registeredAt: time.Now(),
	}

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
	_, exists := cpt.containerIdToInfo[containerID]
	assert.False(t, exists)
}

func TestContainerProcessTreeImpl_GetPidBranch_Success(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
	}

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
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
	}

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
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
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
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
	}

	// Process outside container subtree
	outsideProcess := &apitypes.Process{
		PID:         200,
		PPID:        1, // Parent is init, not shim
		Comm:        "outside",
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

	// Test with target PID not in container's subtree
	result, err := cpt.GetPidBranch(containerID, 200, createSafeMapFromData(fullTree))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target process 200 is not within container")
	assert.Equal(t, apitypes.Process{}, result)
}

func TestContainerProcessTreeImpl_GetPidBranch_DeepTree(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
	}

	// Create a deep tree: shim (50) -> bash (100) -> python (101) -> worker (102) -> task (103)
	taskProcess := &apitypes.Process{
		PID:         103,
		PPID:        102,
		Comm:        "task",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	workerProcess := &apitypes.Process{
		PID:  102,
		PPID: 101,
		Comm: "worker",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "task", PID: 103}: taskProcess,
		},
	}

	pythonProcess := &apitypes.Process{
		PID:  101,
		PPID: 100,
		Comm: "python",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "worker", PID: 102}: workerProcess,
		},
	}

	bashProcess := &apitypes.Process{
		PID:  100,
		PPID: 50, // parent is shim
		Comm: "bash",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "python", PID: 101}: pythonProcess,
		},
	}

	shimProcess := &apitypes.Process{
		PID:  50, // shim
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "bash", PID: 100}: bashProcess,
		},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shimProcess,
		100: bashProcess,
		101: pythonProcess,
		102: workerProcess,
		103: taskProcess,
	}

	// Test getting branch for task (PID 103) - should get entire path from bash to task
	result, err := cpt.GetPidBranch(containerID, 103, createSafeMapFromData(fullTree))
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), result.PID) // Root should be bash
	assert.Equal(t, "bash", result.Comm)

	// Verify the chain: bash -> python -> worker -> task
	assert.Len(t, result.ChildrenMap, 1)
	pythonResult, exists := result.ChildrenMap[apitypes.CommPID{Comm: "python", PID: 101}]
	assert.True(t, exists)
	assert.Equal(t, uint32(101), pythonResult.PID)

	assert.Len(t, pythonResult.ChildrenMap, 1)
	workerResult, exists := pythonResult.ChildrenMap[apitypes.CommPID{Comm: "worker", PID: 102}]
	assert.True(t, exists)
	assert.Equal(t, uint32(102), workerResult.PID)

	assert.Len(t, workerResult.ChildrenMap, 1)
	taskResult, exists := workerResult.ChildrenMap[apitypes.CommPID{Comm: "task", PID: 103}]
	assert.True(t, exists)
	assert.Equal(t, uint32(103), taskResult.PID)
	assert.Len(t, taskResult.ChildrenMap, 0) // task has no children
}

func TestContainerProcessTreeImpl_GetPidBranch_TargetIsShimChild(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
	}

	// Create a simple tree: shim (50) -> nginx (100)
	nginxProcess := &apitypes.Process{
		PID:         100,
		PPID:        50, // parent is shim
		Comm:        "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
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
	}

	// Test getting branch for nginx (direct child of shim)
	result, err := cpt.GetPidBranch(containerID, 100, createSafeMapFromData(fullTree))
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, "nginx", result.Comm)
	assert.Len(t, result.ChildrenMap, 0) // No children in the branch since target is nginx itself
}

func TestContainerProcessTreeImpl_GetPidByContainerID_Success(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
	}

	// Test getting shim PID
	result, err := cpt.GetPidByContainerID(containerID)
	assert.NoError(t, err)
	assert.Equal(t, shimPID, result)
}

func TestContainerProcessTreeImpl_GetPidByContainerID_NotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Test with non-existent container
	result, err := cpt.GetPidByContainerID("non-existent")
	assert.Error(t, err)
	assert.Equal(t, uint32(0), result)
}

func TestContainerProcessTreeImpl_GetPidByContainerID_FallbackToContainerPID(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container without shim PID
	containerID := "test-container-123"
	containerPID := uint32(100)
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      0, // Shim PID not yet discovered
		containerPID: containerPID,
		registeredAt: time.Now(),
	}

	// Test getting PID - should fall back to container PID
	result, err := cpt.GetPidByContainerID(containerID)
	assert.NoError(t, err)
	assert.Equal(t, containerPID, result)
}

func TestContainerProcessTreeImpl_GetShimPIDForProcess_Success(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with containers
	containerID1 := "container-1"
	shimPID1 := uint32(50)
	cpt.containerIdToInfo[containerID1] = &containerInfo{
		shimPID:      shimPID1,
		containerPID: 100,
		registeredAt: time.Now(),
	}

	containerID2 := "container-2"
	shimPID2 := uint32(60)
	cpt.containerIdToInfo[containerID2] = &containerInfo{
		shimPID:      shimPID2,
		containerPID: 200,
		registeredAt: time.Now(),
	}

	// Create tree structure with two containers
	// Container 1: shim1 (50) -> nginx (100)
	nginxProcess := &apitypes.Process{
		PID:         100,
		PPID:        50,
		Comm:        "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	shimProcess1 := &apitypes.Process{
		PID:  50,
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx", PID: 100}: nginxProcess,
		},
	}

	// Container 2: shim2 (60) -> redis (200)
	redisProcess := &apitypes.Process{
		PID:         200,
		PPID:        60,
		Comm:        "redis",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	shimProcess2 := &apitypes.Process{
		PID:  60,
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "redis", PID: 200}: redisProcess,
		},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shimProcess1,
		60:  shimProcess2,
		100: nginxProcess,
		200: redisProcess,
	}

	safeTree := createSafeMapFromData(fullTree)

	// Test getting shim for nginx (PID 100) - should return shim1
	result, found := cpt.GetShimPIDForProcess(100, safeTree)
	assert.True(t, found)
	assert.Equal(t, shimPID1, result)

	// Test getting shim for redis (PID 200) - should return shim2
	result, found = cpt.GetShimPIDForProcess(200, safeTree)
	assert.True(t, found)
	assert.Equal(t, shimPID2, result)
}

func TestContainerProcessTreeImpl_GetShimPIDForProcess_NotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
	}

	shimProcess := &apitypes.Process{
		PID:         50,
		PPID:        1,
		Comm:        "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	// Process outside container
	outsideProcess := &apitypes.Process{
		PID:         300,
		PPID:        1, // Parent is init, not shim
		Comm:        "outside",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shimProcess,
		300: outsideProcess,
	}

	// Test getting shim for process outside container
	result, found := cpt.GetShimPIDForProcess(300, createSafeMapFromData(fullTree))
	assert.False(t, found)
	assert.Equal(t, uint32(0), result)
}

func TestContainerProcessTreeImpl_IsProcessUnderContainer_Success(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
	}

	// Create tree: shim (50) -> nginx (100) -> worker (101)
	workerProcess := &apitypes.Process{
		PID:         101,
		PPID:        100,
		Comm:        "worker",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	nginxProcess := &apitypes.Process{
		PID:  100,
		PPID: 50,
		Comm: "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "worker", PID: 101}: workerProcess,
		},
	}

	shimProcess := &apitypes.Process{
		PID:  50,
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
		101: workerProcess,
	}

	safeTree := createSafeMapFromData(fullTree)

	// Test nginx (direct child of shim)
	assert.True(t, cpt.IsProcessUnderContainer(100, containerID, safeTree))

	// Test worker (grandchild of shim)
	assert.True(t, cpt.IsProcessUnderContainer(101, containerID, safeTree))
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
	assert.False(t, cpt.IsProcessUnderContainer(100, "non-existent", createSafeMapFromData(fullTree)))
}

func TestContainerProcessTreeImpl_IsProcessUnderContainer_ShimNotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container but shim doesn't exist in tree
	containerID := "test-container-123"
	shimPID := uint32(999) // Non-existent in tree
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		100: {
			PID:         100,
			PPID:        1,
			Comm:        "nginx",
			ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
		},
	}

	safeTree := createSafeMapFromData(fullTree)

	// Test with PID 100 (which is the containerPID) - should return true via fallback
	// because the new fallback logic checks if target == containerPID or under containerPID
	assert.True(t, cpt.IsProcessUnderContainer(100, containerID, safeTree))

	// Test with a process outside the container - should return false
	assert.False(t, cpt.IsProcessUnderContainer(1, containerID, safeTree))

	// Test with non-existent process - should return false
	assert.False(t, cpt.IsProcessUnderContainer(999, containerID, safeTree))
}

func TestContainerProcessTreeImpl_IsProcessUnderContainer_ProcessNotFound(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
	}

	shimProcess := &apitypes.Process{
		PID:         50,
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

	// Test with non-existent process
	assert.False(t, cpt.IsProcessUnderContainer(999, containerID, createSafeMapFromData(fullTree)))
}

func TestContainerProcessTreeImpl_IsProcessUnderAnyContainerSubtree_Success(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with multiple containers
	containerID1 := "container-1"
	shimPID1 := uint32(50)
	cpt.containerIdToInfo[containerID1] = &containerInfo{
		shimPID:      shimPID1,
		containerPID: 100,
		registeredAt: time.Now(),
	}

	containerID2 := "container-2"
	shimPID2 := uint32(60)
	cpt.containerIdToInfo[containerID2] = &containerInfo{
		shimPID:      shimPID2,
		containerPID: 200,
		registeredAt: time.Now(),
	}

	// Create tree with two containers
	nginxProcess := &apitypes.Process{
		PID:         100,
		PPID:        50,
		Comm:        "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	shimProcess1 := &apitypes.Process{
		PID:  50,
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx", PID: 100}: nginxProcess,
		},
	}

	redisProcess := &apitypes.Process{
		PID:         200,
		PPID:        60,
		Comm:        "redis",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	shimProcess2 := &apitypes.Process{
		PID:  60,
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "redis", PID: 200}: redisProcess,
		},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shimProcess1,
		60:  shimProcess2,
		100: nginxProcess,
		200: redisProcess,
	}

	safeTree := createSafeMapFromData(fullTree)

	// Test nginx (in container 1)
	assert.True(t, cpt.IsProcessUnderAnyContainerSubtree(100, safeTree))

	// Test redis (in container 2)
	assert.True(t, cpt.IsProcessUnderAnyContainerSubtree(200, safeTree))
}

func TestContainerProcessTreeImpl_IsProcessUnderAnyContainerSubtree_NoContainers(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		100: {
			PID:         100,
			PPID:        1,
			Comm:        "some-process",
			ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
		},
	}

	// No containers registered
	assert.False(t, cpt.IsProcessUnderAnyContainerSubtree(100, createSafeMapFromData(fullTree)))
}

func TestContainerProcessTreeImpl_IsProcessUnderAnyContainerSubtree_OutsideProcess(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	// Pre-populate with a container
	containerID := "test-container-123"
	shimPID := uint32(50)
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      shimPID,
		containerPID: 100,
		registeredAt: time.Now(),
	}

	nginxProcess := &apitypes.Process{
		PID:         100,
		PPID:        50,
		Comm:        "nginx",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	shimProcess := &apitypes.Process{
		PID:  50,
		PPID: 1,
		Comm: "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "nginx", PID: 100}: nginxProcess,
		},
	}

	// Process outside any container
	outsideProcess := &apitypes.Process{
		PID:         300,
		PPID:        1, // Parent is init
		Comm:        "outside",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shimProcess,
		100: nginxProcess,
		300: outsideProcess,
	}

	// Test process outside container
	assert.False(t, cpt.IsProcessUnderAnyContainerSubtree(300, createSafeMapFromData(fullTree)))
}

func TestContainerProcessTreeImpl_RegisterContainerShim(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	containerID := "test-container-123"
	shimPID := uint32(50)
	containerPID := uint32(100)

	// Register a new container
	cpt.RegisterContainerShim(containerID, shimPID, containerPID)

	// Verify container was registered
	info, exists := cpt.containerIdToInfo[containerID]
	assert.True(t, exists)
	assert.Equal(t, shimPID, info.shimPID)
	assert.Equal(t, containerPID, info.containerPID)
}

func TestContainerProcessTreeImpl_RegisterContainerShim_UpdatePending(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	containerID := "test-container-123"
	containerPID := uint32(100)

	// First register without shim PID
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      0, // Pending
		containerPID: containerPID,
		registeredAt: time.Now(),
	}

	// Now register with shim PID
	shimPID := uint32(50)
	cpt.RegisterContainerShim(containerID, shimPID, containerPID)

	// Verify shim PID was updated
	info := cpt.containerIdToInfo[containerID]
	assert.Equal(t, shimPID, info.shimPID)
}

func TestContainerProcessTreeImpl_LazyShimDiscovery(t *testing.T) {
	cpt := NewContainerProcessTree().(*containerProcessTreeImpl)

	containerID := "test-container-123"
	containerPID := uint32(100)

	// Register container without shim PID
	cpt.containerIdToInfo[containerID] = &containerInfo{
		shimPID:      0, // Not yet discovered
		containerPID: containerPID,
		registeredAt: time.Now(),
	}

	// Create tree where container process has parent (shim)
	shimProcess := &apitypes.Process{
		PID:         50,
		PPID:        1,
		Comm:        "containerd-shim",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	containerProcess := &apitypes.Process{
		PID:         100,
		PPID:        50, // Parent is shim
		Comm:        "container-init",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{},
	}

	fullTree := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		50:  shimProcess,
		100: containerProcess,
	}

	safeTree := createSafeMapFromData(fullTree)

	// Try to discover shim PID via process tree
	shimPID := cpt.tryDiscoverShimPID(containerID, safeTree)

	// Verify shim was discovered
	assert.Equal(t, uint32(50), shimPID)

	// Verify it was saved in containerIdToInfo
	info := cpt.containerIdToInfo[containerID]
	assert.Equal(t, uint32(50), info.shimPID)
}
