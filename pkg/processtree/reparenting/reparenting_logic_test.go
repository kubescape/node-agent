package reparenting

import (
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReparentingLogic(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)
	assert.NotNil(t, rl)

	strategies := rl.GetStrategies()
	assert.Len(t, strategies, 4) // containerd, systemd, docker, default

	// Check that all expected strategies are present
	strategyNames := make(map[string]bool)
	for _, strategy := range strategies {
		strategyNames[strategy.Name()] = true
	}

	assert.True(t, strategyNames["containerd"])
	assert.True(t, strategyNames["systemd"])
	assert.True(t, strategyNames["docker"])
	assert.True(t, strategyNames["default"])
}

func TestContainerdStrategy(t *testing.T) {
	cs := &ContainerdStrategy{}
	assert.Equal(t, "containerd", cs.Name())

	// Test IsApplicable - should return false when containerTree is nil
	assert.False(t, cs.IsApplicable(100, nil, make(map[uint32]*apitypes.Process)))

	// Test GetNewParentPID - should return 1 when no container tree
	newParentPID := cs.GetNewParentPID(100, nil, nil, make(map[uint32]*apitypes.Process))
	assert.Equal(t, uint32(1), newParentPID)
}

func TestSystemdStrategy(t *testing.T) {
	ss := &SystemdStrategy{}
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
	ds := &DockerStrategy{}
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
	defs := &DefaultStrategy{}
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
