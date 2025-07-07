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
	assert.Len(t, strategies, 4) // containerd, docker, systemd, default

	// Check that all expected strategies are present
	strategyNames := make(map[string]bool)
	for _, strategy := range strategies {
		strategyNames[strategy.Name()] = true
	}

	assert.True(t, strategyNames["containerd"])
	assert.True(t, strategyNames["docker"])
	assert.True(t, strategyNames["systemd"])
	assert.True(t, strategyNames["default"])

	// Explicitly verify the order: containerd → docker → systemd → default
	assert.Equal(t, "containerd", strategies[0].Name())
	assert.Equal(t, "docker", strategies[1].Name())
	assert.Equal(t, "systemd", strategies[2].Name())
	assert.Equal(t, "default", strategies[3].Name())
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

func TestSystemdStrategy(t *testing.T) {
	ss := &strategies.SystemdStrategy{}
	assert.Equal(t, "systemd", ss.Name())

	processMap := map[uint32]*apitypes.Process{
		100: {
			PID:  100,
			PPID: 1,
			Comm: "systemd-user-sessions",
		},
		200: {
			PID:  200,
			PPID: 100,
			Comm: "some-process",
		},
		1: {
			PID:  1,
			PPID: 0,
			Comm: "systemd",
		},
	}

	// Test IsApplicable with systemd process
	assert.True(t, ss.IsApplicable(100, nil, processMap))

	// Test IsApplicable with child of systemd process
	assert.True(t, ss.IsApplicable(200, nil, processMap))

	// Test IsApplicable with non-systemd process (not under systemd)
	processMap[300] = &apitypes.Process{
		PID:  300,
		PPID: 999, // Different parent, not systemd
		Comm: "nginx",
	}
	assert.False(t, ss.IsApplicable(300, nil, processMap))

	// Test GetNewParentPID
	newParentPID := ss.GetNewParentPID(100, nil, nil, processMap)
	assert.Equal(t, uint32(1), newParentPID)
}

func TestDockerStrategy(t *testing.T) {
	ds := &strategies.DockerStrategy{}
	assert.Equal(t, "docker", ds.Name())

	processMap := map[uint32]*apitypes.Process{
		100: {
			PID:  100,
			PPID: 1,
			Comm: "dockerd",
		},
		200: {
			PID:  200,
			PPID: 100,
			Comm: "docker-proxy",
		},
	}

	// Test IsApplicable with docker process
	assert.True(t, ds.IsApplicable(100, nil, processMap))

	// Test IsApplicable with child of docker process
	assert.True(t, ds.IsApplicable(200, nil, processMap))

	// Test IsApplicable with non-docker process
	processMap[300] = &apitypes.Process{
		PID:  300,
		PPID: 1,
		Comm: "nginx",
	}
	assert.False(t, ds.IsApplicable(300, nil, processMap))

	// Test GetNewParentPID
	newParentPID := ds.GetNewParentPID(200, nil, nil, processMap)
	assert.Equal(t, uint32(100), newParentPID) // Should return dockerd PID
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
		100: {
			PID:  100,
			PPID: 1,
			Comm: "parent",
		},
		200: children[0],
		201: children[1],
	}

	result := rl.HandleProcessExit(100, children, nil, processMap)
	assert.Equal(t, uint32(1), result.NewParentPID) // Should use default strategy
	assert.Equal(t, "default", result.Strategy)
	// Note: verification will fail in tests since we can't access real procfs
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

func TestDockerStrategy_Hierarchy(t *testing.T) {
	ds := &strategies.DockerStrategy{}

	// Create a docker hierarchy: dockerd -> docker-proxy -> nginx -> worker
	processMap := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "init",
		},
		100: {
			PID:  100,
			PPID: 1,
			Comm: "dockerd",
		},
		200: {
			PID:  200,
			PPID: 100,
			Comm: "docker-proxy",
		},
		300: {
			PID:  300,
			PPID: 200,
			Comm: "nginx",
		},
		400: {
			PID:  400,
			PPID: 300,
			Comm: "nginx-worker",
		},
	}

	// Test that all processes in the docker hierarchy are applicable
	assert.True(t, ds.IsApplicable(100, nil, processMap)) // dockerd
	assert.True(t, ds.IsApplicable(200, nil, processMap)) // docker-proxy
	assert.True(t, ds.IsApplicable(300, nil, processMap)) // nginx
	assert.True(t, ds.IsApplicable(400, nil, processMap)) // nginx-worker

	// Test that processes outside the docker hierarchy are not applicable
	processMap[500] = &apitypes.Process{
		PID:  500,
		PPID: 1,
		Comm: "nginx",
	}
	assert.False(t, ds.IsApplicable(500, nil, processMap))
}

func TestSystemdStrategy_Hierarchy(t *testing.T) {
	ss := &strategies.SystemdStrategy{}

	// Create a systemd hierarchy: systemd -> systemd-user-sessions -> user-process
	processMap := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "systemd",
		},
		100: {
			PID:  100,
			PPID: 1,
			Comm: "systemd-user-sessions",
		},
		200: {
			PID:  200,
			PPID: 100,
			Comm: "user-process",
		},
		300: {
			PID:  300,
			PPID: 200,
			Comm: "child-process",
		},
	}

	// Test that all processes in the systemd hierarchy are applicable
	assert.True(t, ss.IsApplicable(1, nil, processMap))   // systemd
	assert.True(t, ss.IsApplicable(100, nil, processMap)) // systemd-user-sessions
	assert.True(t, ss.IsApplicable(200, nil, processMap)) // user-process
	assert.True(t, ss.IsApplicable(300, nil, processMap)) // child-process

	// Test that processes outside the systemd hierarchy are not applicable
	// Create a process that's not under systemd (different parent chain)
	processMap[500] = &apitypes.Process{
		PID:  500,
		PPID: 999, // Different parent, not systemd
		Comm: "nginx",
	}
	assert.False(t, ss.IsApplicable(500, nil, processMap))

	// Test that a process with systemd as direct parent should be applicable
	processMap[600] = &apitypes.Process{
		PID:  600,
		PPID: 1, // Direct child of systemd
		Comm: "nginx",
	}
	assert.True(t, ss.IsApplicable(600, nil, processMap))
}

func TestStrategyPriority(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	// Create a mock container tree that indicates the process is under containerd
	mockContainerTree := &MockContainerTree{
		shimPID:            50,
		containerProcesses: map[uint32]bool{100: true},
	}

	// Create a process that could be under both containerd and docker
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
			Comm: "systemd",
		},
	}

	children := []*apitypes.Process{
		{
			PID:  200,
			PPID: 100,
			Comm: "child",
		},
	}

	// Test that containerd strategy takes priority (first in order)
	result := rl.HandleProcessExit(100, children, mockContainerTree, processMap)
	assert.Equal(t, "containerd", result.Strategy)
	assert.Equal(t, uint32(50), result.NewParentPID) // Should reparent to shim
}

func TestStrategyOrderScanning(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	// Create a process that's under docker but not containerd
	processMap := map[uint32]*apitypes.Process{
		100: {
			PID:  100,
			PPID: 1,
			Comm: "dockerd",
		},
		200: {
			PID:  200,
			PPID: 100,
			Comm: "docker-proxy",
		},
		300: {
			PID:  300,
			PPID: 200,
			Comm: "nginx",
		},
		1: {
			PID:  1,
			PPID: 0,
			Comm: "systemd",
		},
	}

	children := []*apitypes.Process{
		{
			PID:  400,
			PPID: 300,
			Comm: "child",
		},
	}

	// Test that docker strategy is selected (containerd not applicable, docker is)
	result := rl.HandleProcessExit(300, children, nil, processMap)
	assert.Equal(t, "docker", result.Strategy)
	assert.Equal(t, uint32(100), result.NewParentPID) // Should reparent to dockerd
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
			Comm: "systemd",
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

	// Test that systemd strategy is selected (containerd and docker not applicable)
	result := rl.HandleProcessExit(100, children, nil, processMap)
	assert.Equal(t, "systemd", result.Strategy)
	assert.Equal(t, uint32(1), result.NewParentPID) // Should reparent to systemd

	// Note: In a real scenario with procfs mismatch, the actual PPID from procfs would be used
	// This would require mocking the procfs interface to test the mismatch scenario
}

func TestFirstApplicableStrategyWins(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)

	// Create a process that could be under multiple hierarchies
	// This tests that the first applicable strategy in the order wins
	processMap := map[uint32]*apitypes.Process{
		1: {
			PID:  1,
			PPID: 0,
			Comm: "systemd",
		},
		100: {
			PID:  100,
			PPID: 1,
			Comm: "dockerd", // This could be both docker and systemd
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

	// Test that docker strategy is selected (first applicable in order: containerd -> docker -> systemd -> default)
	// Even though the process is also under systemd, docker comes first in the order
	result := rl.HandleProcessExit(200, children, nil, processMap)
	assert.Equal(t, "docker", result.Strategy)
	assert.Equal(t, uint32(100), result.NewParentPID) // Should reparent to dockerd
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
func (mct *MockContainerTree) GetContainerSubtree(containerID string, targetPID uint32, fullTree map[uint32]*apitypes.Process) (apitypes.Process, error) {
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
