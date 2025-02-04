package applicationprofilemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ApplicationProfileManagerMock struct {
}

var _ ApplicationProfileManagerClient = (*ApplicationProfileManagerMock)(nil)

func CreateApplicationProfileManagerMock() *ApplicationProfileManagerMock {
	return &ApplicationProfileManagerMock{}
}

func (a ApplicationProfileManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}

func (a ApplicationProfileManagerMock) RegisterPeekFunc(_ func(mntns uint64) ([]string, error)) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportCapability(_, _ string) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportFileExec(_ string, _ events.ExecEvent) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportFileOpen(_ string, _ events.OpenEvent) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportDroppedEvent(_ string) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportHTTPEvent(_ string, _ *tracerhttptype.Event) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportRulePolicy(_, _, _ string, _ bool) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportIdentifiedCallStack(_ string, _ *v1beta1.IdentifiedCallStack) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportSymlinkEvent(_ string, _ *tracersymlinktype.Event) {
	// noop
}

func (a ApplicationProfileManagerMock) ReportHardlinkEvent(_ string, _ *tracerhardlinktype.Event) {
	// noop
}

func (a ApplicationProfileManagerMock) ContainerReachedMaxTime(_ string) {
	// noop
}
