package strategies

import (
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/stretchr/testify/assert"
)

type MockContainerProcessTree struct {
	shimPID uint32
}

func (m *MockContainerProcessTree) ContainerCallback(notif containercollection.PubSubEvent) {}

func (m *MockContainerProcessTree) GetPidBranch(containerID string, targetPID uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) (apitypes.Process, error) {
	return apitypes.Process{}, nil
}

func (m *MockContainerProcessTree) GetShimPIDForProcess(pid uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) (uint32, bool) {
	if _, ok := fullTree.Load(pid); ok {
		return m.shimPID, true
	}
	return 0, false
}

func (m *MockContainerProcessTree) GetPidByContainerID(containerID string) (uint32, error) {
	return m.shimPID, nil
}

func (m *MockContainerProcessTree) IsProcessUnderAnyContainerSubtree(pid uint32, fullTree *maps.SafeMap[uint32, *apitypes.Process]) bool {
	return true
}

func (m *MockContainerProcessTree) IsProcessUnderContainer(pid uint32, containerID string, fullTree *maps.SafeMap[uint32, *apitypes.Process]) bool {
	return true
}

func TestContainerStrategy_GetNewParentPID(t *testing.T) {
	// Setup
	strategy := &ContainerStrategy{}
	processMap := &maps.SafeMap[uint32, *apitypes.Process]{}

	shimPID := uint32(100)
	containerInitPID := uint32(101)
	parentPID := uint32(102)
	childPID := uint32(103)

	// Build tree: Shim -> Init -> Parent -> Child
	processMap.Set(shimPID, &apitypes.Process{PID: shimPID, PPID: 1, Comm: "shim"})
	processMap.Set(containerInitPID, &apitypes.Process{PID: containerInitPID, PPID: shimPID, Comm: "init"})
	processMap.Set(parentPID, &apitypes.Process{PID: parentPID, PPID: containerInitPID, Comm: "parent"})
	processMap.Set(childPID, &apitypes.Process{PID: childPID, PPID: parentPID, Comm: "child"})

	mockContainerTree := &MockContainerProcessTree{shimPID: shimPID}

	children := []*apitypes.Process{
		{PID: childPID, PPID: parentPID},
	}

	// Execute
	newParent := strategy.GetNewParentPID(parentPID, children, mockContainerTree, processMap)

	// Assert
	// We expect the new parent to be the container init process (101), not the shim (100).
	assert.Equal(t, containerInitPID, newParent, "Should reparent to container init process")
}

func TestContainerStrategy_GetNewParentPID_InitExits(t *testing.T) {
	// Setup
	strategy := &ContainerStrategy{}
	processMap := &maps.SafeMap[uint32, *apitypes.Process]{}

	shimPID := uint32(100)
	containerInitPID := uint32(101)
	childPID := uint32(102)

	// Build tree: Shim -> Init -> Child
	processMap.Set(shimPID, &apitypes.Process{PID: shimPID, PPID: 1, Comm: "shim"})
	processMap.Set(containerInitPID, &apitypes.Process{PID: containerInitPID, PPID: shimPID, Comm: "init"})
	processMap.Set(childPID, &apitypes.Process{PID: childPID, PPID: containerInitPID, Comm: "child"})

	mockContainerTree := &MockContainerProcessTree{shimPID: shimPID}

	children := []*apitypes.Process{
		{PID: childPID, PPID: containerInitPID},
	}

	// Execute - Init process exits
	newParent := strategy.GetNewParentPID(containerInitPID, children, mockContainerTree, processMap)

	// Assert
	// When init exits, children should go to shim
	assert.Equal(t, shimPID, newParent, "Should reparent to shim process when init exits")
}
