package containerprofilemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
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

func (a ContainerProfileManagerMock) RegisterPeekFunc(_ func(mntns uint64) ([]string, error)) {
	// noop
}

func (a ContainerProfileManagerMock) ReportCapability(_, _ string) {
	// noop
}

func (a ContainerProfileManagerMock) ReportFileExec(_ string, _ events.ExecEvent) {
	// noop
}

func (a ContainerProfileManagerMock) ReportFileOpen(_ string, _ events.OpenEvent) {
	// noop
}

func (a ContainerProfileManagerMock) ReportDroppedEvent(_ string) {
	// noop
}

func (a ContainerProfileManagerMock) ReportHTTPEvent(_ string, _ *tracerhttptype.Event) {
	// noop
}

func (a ContainerProfileManagerMock) ReportRulePolicy(_, _, _ string, _ bool) {
	// noop
}

func (a ContainerProfileManagerMock) ReportIdentifiedCallStack(_ string, _ *v1beta1.IdentifiedCallStack) {
	// noop
}

func (a ContainerProfileManagerMock) ReportSymlinkEvent(_ string, _ *tracersymlinktype.Event) {
	// noop
}

func (a ContainerProfileManagerMock) ReportHardlinkEvent(_ string, _ *tracerhardlinktype.Event) {
	// noop
}

func (a ContainerProfileManagerMock) RegisterForContainerEndOfLife(_ chan *containercollection.Container) {
	// noop
}

func (a ContainerProfileManagerMock) ReportNetworkEvent(_ string, _ *tracernetworktype.Event) {
	// noop
}
