package processtree

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
)

// ProcessTreeManagerMock implements the ProcessTreeManager interface for testing
type ProcessTreeManagerMock struct {
	pidList []uint32
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
func (m *ProcessTreeManagerMock) GetContainerProcessTree(containerID string, pid uint32, useCache bool) (apitypes.Process, error) {
	return apitypes.Process{}, nil
}

// GetContainerIDForPid returns an empty string for testing
func (m *ProcessTreeManagerMock) GetContainerIDForPid(pid uint32) (string, error) {
	return "", nil
}

// ReportEvent is a no-op for testing
func (m *ProcessTreeManagerMock) ReportEvent(eventType utils.EventType, event utils.K8sEvent) error {
	return nil
}

// GetPidList returns the mock PID list
func (m *ProcessTreeManagerMock) GetPidList() []uint32 {
	return m.pidList
}
