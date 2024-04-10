package processtreemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
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
