package processtree

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
)

// ProcessTreeManagerMock implements the ProcessTreeManager interface for testing
type ProcessTreeManagerMock struct {
	pidList    []uint32
	bootTimeNs map[uint32]uint64
}

var _ ProcessTreeManager = (*ProcessTreeManagerMock)(nil)

// NewProcessTreeManagerMock creates a new mock process tree manager
func NewProcessTreeManagerMock() *ProcessTreeManagerMock {
	return &ProcessTreeManagerMock{
		pidList: []uint32{},
	}
}

// SetPidList sets the list of PIDs that the mock will return
func (m *ProcessTreeManagerMock) SetPidList(pids []uint32) {
	m.pidList = pids
}

// Start is a no-op for testing
func (m *ProcessTreeManagerMock) Start() {
	// no-op
}

// Stop is a no-op for testing
func (m *ProcessTreeManagerMock) Stop() {
	// no-op
}

// GetContainerProcessTree returns an empty process for testing
func (m *ProcessTreeManagerMock) GetContainerProcessTree(containerID string, pid uint32, useCache bool) (armotypes.Process, error) {
	return armotypes.Process{}, nil
}

// ReportEvent is a no-op for testing
func (m *ProcessTreeManagerMock) ReportEvent(eventType utils.EventType, event utils.K8sEvent) error {
	return nil
}

// GetPidList returns the mock PID list
func (m *ProcessTreeManagerMock) GetPidList() []uint32 {
	return m.pidList
}

// GetProcessBootTimeNs returns the configured start time for a pid, or 0 for an
// unknown one — matching the real manager's "0 means unknown" contract.
func (m *ProcessTreeManagerMock) GetProcessBootTimeNs(pid uint32) uint64 {
	return m.bootTimeNs[pid]
}

// SetProcessBootTimeNs sets the boot-relative start time the mock reports for a pid.
func (m *ProcessTreeManagerMock) SetProcessBootTimeNs(pid uint32, ns uint64) {
	if m.bootTimeNs == nil {
		m.bootTimeNs = make(map[uint32]uint64)
	}
	m.bootTimeNs[pid] = ns
}
