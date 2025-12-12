package containerprofilemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ContainerProfileManagerMock struct {
}

var _ ContainerProfileManagerClient = (*ContainerProfileManagerMock)(nil)

func CreateContainerProfileManagerMock() *ContainerProfileManagerMock {
	return &ContainerProfileManagerMock{}
}

func (a ContainerProfileManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}

func (a ContainerProfileManagerMock) ReportSyscall(_ string, _ string) {
	// noop
}

func (a ContainerProfileManagerMock) ReportCapability(_, _ string) {
	// noop
}

func (a ContainerProfileManagerMock) ReportFileExec(_ string, _ utils.ExecEvent) {
	// noop
}

func (a ContainerProfileManagerMock) ReportFileOpen(_ string, _ utils.OpenEvent) {
	// noop
}

func (a ContainerProfileManagerMock) ReportDroppedEvent(_ string) {
	// noop
}

func (a ContainerProfileManagerMock) ReportHTTPEvent(_ string, _ utils.HttpEvent) {
	// noop
}

func (a ContainerProfileManagerMock) ReportRulePolicy(_, _, _ string, _ bool) {
	// noop
}

func (a ContainerProfileManagerMock) ReportIdentifiedCallStack(_ string, _ *v1beta1.IdentifiedCallStack) {
	// noop
}

func (a ContainerProfileManagerMock) ReportSymlinkEvent(_ string, _ utils.LinkEvent) {
	// noop
}

func (a ContainerProfileManagerMock) ReportHardlinkEvent(_ string, _ utils.LinkEvent) {
	// noop
}

func (a ContainerProfileManagerMock) RegisterForContainerEndOfLife(_ chan *containercollection.Container) {
	// noop
}

func (a ContainerProfileManagerMock) ReportNetworkEvent(_ string, _ utils.NetworkEvent) {
	// noop
}

func (a ContainerProfileManagerMock) OnQueueError(_ *v1beta1.ContainerProfile, _ string, _ error) {
	// noop
}
