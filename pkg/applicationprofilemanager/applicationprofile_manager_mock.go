package applicationprofilemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
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

func (a ApplicationProfileManagerMock) ContainerReachedMaxTime(_ string) {
	// noop
}
