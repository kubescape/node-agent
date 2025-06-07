package containerprofilemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ContainerProfileManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	RegisterPeekFunc(peek func(mntns uint64) ([]string, error))
	ReportCapability(containerID, capability string)
	ReportFileExec(containerID string, event events.ExecEvent)
	ReportFileOpen(containerID string, event events.OpenEvent)
	ReportHTTPEvent(containerID string, event *tracerhttptype.Event)
	ReportRulePolicy(containerID, ruleId, allowedProcess string, allowedContainer bool)
	ReportIdentifiedCallStack(containerID string, callStack *v1beta1.IdentifiedCallStack)
	ReportSymlinkEvent(containerID string, event *tracersymlinktype.Event)
	ReportHardlinkEvent(containerID string, event *tracerhardlinktype.Event)
	ReportNetworkEvent(containerID string, event *tracernetworktype.Event)
	ReportDroppedEvent(containerID string)
	RegisterForContainerEndOfLife(notificationChannel chan *containercollection.Container)
}

type Enricher interface {
	EnrichEvent(containerID string, event utils.EnrichEvent, callID string)
}
