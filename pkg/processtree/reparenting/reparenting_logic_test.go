package reparenting

import (
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/reparenting/strategies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReparentingLogic(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)
	assert.NotNil(t, rl)

	strategies := rl.GetStrategies()
	assert.Len(t, strategies, 2) // containerd, default only

	// Check that all expected strategies are present
	strategyNames := make(map[string]bool)
	for _, strategy := range strategies {
		strategyNames[strategy.Name()] = true
	}

	assert.True(t, strategyNames["containerd"])
	assert.True(t, strategyNames["default"])

	// Explicitly verify the order: containerd → default
	assert.Equal(t, "containerd", strategies[0].Name())
	assert.Equal(t, "default", strategies[1].Name())
}

func TestContainerdStrategy(t *testing.T) {
	cs := &strategies.ContainerdStrategy{}
	assert.Equal(t, "containerd", cs.Name())

	// Test IsApplicable - should return false when containerTree is nil
	assert.False(t, cs.IsApplicable(100, nil, make(map[uint32]*apitypes.Process)))

	// Test GetNewParentPID - should return 1 when no container tree
	newParentPID := cs.GetNewParentPID(100, nil, nil, make(map[uint32]*apitypes.Process))
	assert.Equal(t, uint32(1), newParentPID)
}

func TestDefaultStrategy(t *testing.T) {
	defs := &strategies.DefaultStrategy{}
	assert.Equal(t, "default", defs.Name())

	// Test IsApplicable - should always return true
	assert.True(t, defs.IsApplicable(100, nil, make(map[uint32]*apitypes.Process)))

	// Test GetNewParentPID - should always return 1
	newParentPID := defs.GetNewParentPID(100, nil, nil, make(map[uint32]*apitypes.Process))
	assert.Equal(t, uint32(1), newParentPID)
}

func TestReparentingLogic_HandleProcessExit_NoChildren(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	result := rl.HandleProcessExit(100, nil, nil, make(map[uint32]*apitypes.Process))
	assert.Equal(t, uint32(0), result.NewParentPID)
	assert.Equal(t, "no_children", result.Strategy)
	assert.True(t, result.Verified)
	assert.Nil(t, result.Error)
}

func TestReparentingLogic_HandleProcessExit_WithChildren(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	children := []*apitypes.Process{
		{
			PID:  200,
			PPID: 100,
			Comm: "child1",
		},
		{
			PID:  201,
			PPID: 100,
			Comm: "child2",
		},
	}

	processMap := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		100: {
			PID:  100,
			PPID: 1,
			Comm: "parent",
		},
		200: children[0],
		201: children[1],
	}

	result := rl.HandleProcessExit(100, children, nil, processMap)
	assert.Equal(t, uint32(1), result.NewParentPID) // Should use PPID of exiting process
	assert.Equal(t, "ppid", result.Strategy)
	assert.True(t, result.Verified)
	assert.Nil(t, result.Error)
}

func TestReparentingLogic_AddStrategy(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	initialCount := len(rl.GetStrategies())

	// Add a custom strategy
	customStrategy := &CustomTestStrategy{}
	rl.AddStrategy(customStrategy)

	strategies := rl.GetStrategies()
	assert.Len(t, strategies, initialCount+1)

	// Check that our custom strategy was added
	found := false
	for _, strategy := range strategies {
		if strategy.Name() == "custom_test" {
			found = true
			break
		}
	}
	assert.True(t, found)
}

// CustomTestStrategy is a test strategy for testing purposes
type CustomTestStrategy struct{}

func (cts *CustomTestStrategy) Name() string {
	return "custom_test"
}

func (cts *CustomTestStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	return exitingPID == 999 // Only applicable for PID 999
}

func (cts *CustomTestStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	return 888 // Always return PID 888
}

func TestStrategyPriority(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	// Create a mock container tree that indicates the process is under containerd
	mockContainerTree := &MockContainerTree{
		shimPID:            50,
		containerProcesses: map[uint32]bool{100: true},
	}

	// Create a process that could be under containerd but PPID takes priority
	processMap := map[uint32]*apitypes.Process{
		100: {
			PID:  100,
			PPID: 50, // shim PID
			Comm: "nginx",
		},
		50: {
			PID:  50,
			PPID: 1,
			Comm: "containerd-shim",
		},
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	children := []*apitypes.Process{
		{
			PID:  200,
			PPID: 100,
			Comm: "child",
		},
	}

	// Test that PPID strategy takes priority over containerd strategy
	result := rl.HandleProcessExit(100, children, mockContainerTree, processMap)
	assert.Equal(t, "ppid", result.Strategy)
	assert.Equal(t, uint32(50), result.NewParentPID) // Should reparent to PPID (which is also shim)
}

func TestStrategyOrderScanning(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	// Create a process that should use PPID
	processMap := map[uint32]*apitypes.Process{
		100: {
			PID:  100,
			PPID: 1,
			Comm: "daemon",
		},
		200: {
			PID:  200,
			PPID: 100,
			Comm: "worker",
		},
		300: {
			PID:  300,
			PPID: 200,
			Comm: "nginx",
		},
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
	}

	children := []*apitypes.Process{
		{
			PID:  400,
			PPID: 300,
			Comm: "child",
		},
	}

	// Test that PPID strategy is selected first
	result := rl.HandleProcessExit(300, children, nil, processMap)
	assert.Equal(t, "ppid", result.Strategy)
	assert.Equal(t, uint32(200), result.NewParentPID) // Should reparent to PPID
}

func TestProcfsDataUsageOnMismatch(t *testing.T) {
	// This test would require mocking procfs to simulate a mismatch
	// For now, we'll test the logic structure

	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	// Create a simple process tree
	processMap := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		100: {
			PID:  100,
			PPID: 1,
			Comm: "nginx",
		},
	}

	children := []*apitypes.Process{
		{
			PID:  200,
			PPID: 100,
			Comm: "child",
		},
	}

	// Test that PPID strategy is selected first
	result := rl.HandleProcessExit(100, children, nil, processMap)
	assert.Equal(t, "ppid", result.Strategy)
	assert.Equal(t, uint32(1), result.NewParentPID) // Should reparent to PPID

	// Note: In a real scenario with procfs mismatch, the actual PPID from procfs would be used
	// This would require mocking the procfs interface to test the mismatch scenario
}

func TestFirstApplicableStrategyWins(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	// Create a process that should use PPID first
	processMap := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		100: {
			PID:  100,
			PPID: 1,
			Comm: "daemon",
		},
		200: {
			PID:  200,
			PPID: 100,
			Comm: "nginx",
		},
	}

	children := []*apitypes.Process{
		{
			PID:  300,
			PPID: 200,
			Comm: "child",
		},
	}

	// Test that PPID strategy is selected first (highest priority)
	result := rl.HandleProcessExit(200, children, nil, processMap)
	assert.Equal(t, "ppid", result.Strategy)
	assert.Equal(t, uint32(100), result.NewParentPID) // Should reparent to PPID
}

func TestPPIDReparenting(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	// Test case where PPID exists and is valid
	processMap := map[uint32]*apitypes.Process{
		50: {
			PID:  50,
			PPID: 1,
			Comm: "parent",
		},
		100: {
			PID:  100,
			PPID: 50,
			Comm: "exiting",
		},
		200: {
			PID:  200,
			PPID: 100,
			Comm: "child",
		},
	}

	children := []*apitypes.Process{
		{
			PID:  200,
			PPID: 100,
			Comm: "child",
		},
	}

	result := rl.HandleProcessExit(100, children, nil, processMap)
	assert.Equal(t, uint32(50), result.NewParentPID) // Should use PPID of exiting process
	assert.Equal(t, "ppid", result.Strategy)
	assert.True(t, result.Verified)
	assert.Nil(t, result.Error)
}

func TestPPIDReparentingFallback(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	// Test case where PPID doesn't exist in processMap
	processMap := map[uint32]*apitypes.Process{
		100: {
			PID:  100,
			PPID: 999, // PPID doesn't exist in processMap
			Comm: "exiting",
		},
		200: {
			PID:  200,
			PPID: 100,
			Comm: "child",
		},
	}

	children := []*apitypes.Process{
		{
			PID:  200,
			PPID: 100,
			Comm: "child",
		},
	}

	result := rl.HandleProcessExit(100, children, nil, processMap)
	// Should fallback to default strategy since PPID doesn't exist
	assert.Equal(t, uint32(1), result.NewParentPID)
	assert.Equal(t, "default", result.Strategy)
	assert.True(t, result.Verified)
	assert.Nil(t, result.Error)
}

func TestPPIDReparentingWithContainerd(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	// Create a mock container tree that indicates the process is under containerd
	mockContainerTree := &MockContainerTree{
		shimPID:            50,
		containerProcesses: map[uint32]bool{100: true},
	}

	// Test case where PPID doesn't exist, but containerd strategy applies
	processMap := map[uint32]*apitypes.Process{
		50: {
			PID:  50,
			PPID: 1,
			Comm: "containerd-shim",
		},
		100: {
			PID:  100,
			PPID: 999, // PPID doesn't exist in processMap
			Comm: "exiting",
		},
		200: {
			PID:  200,
			PPID: 100,
			Comm: "child",
		},
	}

	children := []*apitypes.Process{
		{
			PID:  200,
			PPID: 100,
			Comm: "child",
		},
	}

	result := rl.HandleProcessExit(100, children, mockContainerTree, processMap)
	// Should use containerd strategy since PPID doesn't exist
	assert.Equal(t, uint32(50), result.NewParentPID) // Should use shim PID
	assert.Equal(t, "containerd", result.Strategy)
	assert.True(t, result.Verified)
	assert.Nil(t, result.Error)
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
func (mct *MockContainerTree) GetPidBranch(containerID string, targetPID uint32, fullTree map[uint32]*apitypes.Process) (apitypes.Process, error) {
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

func (mct *MockContainerTree) GetPidByContainerID(containerID string) (uint32, error) {
	return 0, nil
}
