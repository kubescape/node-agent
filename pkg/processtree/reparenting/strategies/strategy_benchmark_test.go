package strategies

import (
	"fmt"
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

// mockContainerTree is a mock implementation for benchmarking
// It simulates a container tree with a large number of processes

type mockContainerTree struct {
	containerProcesses map[uint32]bool
}

func (m *mockContainerTree) IsProcessUnderAnyContainerSubtree(pid uint32, fullTree map[uint32]*apitypes.Process) bool {
	return m.containerProcesses[pid]
}
func (m *mockContainerTree) GetShimPIDForProcess(pid uint32, fullTree map[uint32]*apitypes.Process) (uint32, bool) {
	return 0, false
}
func (m *mockContainerTree) ContainerCallback(_ containercollection.PubSubEvent) {}
func (m *mockContainerTree) GetContainerTreeNodes(_ string, _ map[uint32]*apitypes.Process) ([]apitypes.Process, error) {
	return nil, nil
}
func (m *mockContainerTree) GetContainerSubtree(_ string, _ uint32, _ map[uint32]*apitypes.Process) (apitypes.Process, error) {
	return apitypes.Process{}, nil
}
func (m *mockContainerTree) ListContainers() []string { return nil }
func (m *mockContainerTree) IsPPIDUnderAnyContainerSubtree(ppid uint32, fullTree map[uint32]*apitypes.Process) bool {
	return m.containerProcesses[ppid]
}
func (m *mockContainerTree) SetShimPIDForTesting(_ string, _ uint32) {}

func makeLargeProcessMap(size int, dockerEvery int, systemdEvery int) map[uint32]*apitypes.Process {
	processMap := make(map[uint32]*apitypes.Process, size)
	for i := 1; i <= size; i++ {
		comm := fmt.Sprintf("proc-%d", i)
		if dockerEvery > 0 && i%dockerEvery == 0 {
			comm = "dockerd"
		}
		if systemdEvery > 0 && i%systemdEvery == 0 {
			comm = "systemd"
		}
		processMap[uint32(i)] = &apitypes.Process{
			PID:  uint32(i),
			PPID: uint32(i - 1),
			Comm: comm,
		}
	}
	return processMap
}

func BenchmarkContainerdStrategy_IsApplicable(b *testing.B) {
	size := 100_000
	containerPIDs := make(map[uint32]bool)
	for i := 1; i <= size; i += 1000 {
		containerPIDs[uint32(i)] = true
	}
	containerTree := &mockContainerTree{containerProcesses: containerPIDs}
	processMap := makeLargeProcessMap(size, 0, 0)
	cs := &ContainerdStrategy{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pid := uint32((i % size) + 1)
		_ = cs.IsApplicable(pid, containerTree, processMap)
	}
}

func BenchmarkDockerStrategy_IsApplicable(b *testing.B) {
	size := 100_000
	processMap := makeLargeProcessMap(size, 1000, 0)
	ds := &DockerStrategy{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pid := uint32((i % size) + 1)
		_ = ds.IsApplicable(pid, nil, processMap)
	}
}

func BenchmarkSystemdStrategy_IsApplicable(b *testing.B) {
	size := 100_000
	processMap := makeLargeProcessMap(size, 0, 1000)
	ss := &SystemdStrategy{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pid := uint32((i % size) + 1)
		_ = ss.IsApplicable(pid, nil, processMap)
	}
}
