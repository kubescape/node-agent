package applicationprofilemanager

import containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"

type ApplicationProfileManagerMock struct {
}

var _ ApplicationProfileManagerClient = (*ApplicationProfileManagerMock)(nil)

func CreateApplicationProfileManagerMock() *ApplicationProfileManagerMock {
	return &ApplicationProfileManagerMock{}
}

func (a ApplicationProfileManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportCapability(_, _ string) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportFileExec(_, _ string, _ []string) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportFileOpen(_, _ string, _ []string) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportSyscallEvent(_ string, _ string) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportDroppedEvent(_ string) {
	// noop
}
func (a ApplicationProfileManagerMock) ContainerReachedMaxTime(_ string) {
	// noop
}
