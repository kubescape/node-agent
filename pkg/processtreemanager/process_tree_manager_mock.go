package processtreemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

type ProcessTreeManagerMock struct {
}

var _ ProcessTreeManagerClient = (*ProcessTreeManagerMock)(nil)

func CreateProcessTreeManagerMock() *ProcessTreeManagerMock {
	return &ProcessTreeManagerMock{}
}

func (r ProcessTreeManagerMock) ReportFileExec(_ tracerexectype.Event) {
	// noop
}

func (r ProcessTreeManagerMock) ContainerCallback(notif containercollection.PubSubEvent) {
	// noop
}

func (r ProcessTreeManagerMock) GetProcessTreeByContainerId(containerID string) *apitypes.Process {
	return nil
}

func (r ProcessTreeManagerMock) GetTreeTrackingByContainerId(containerID string) *TreeTracking {
	return nil
}

func (r ProcessTreeManagerMock) GetProcessByPid(containerID string, pid uint32) *apitypes.Process {
	return nil
}

func (r ProcessTreeManagerMock) SetTreeTrackingByContainerId(containerID string, treeTracking *TreeTracking) {
	// noop
}
