package containerprofilemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ContainerProfileManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ReportCapability(containerID, capability string)
	ReportFileExec(containerID string, event *utils.DatasourceEvent)
	ReportFileOpen(containerID string, event *utils.DatasourceEvent)
	ReportHTTPEvent(containerID string, event *tracerhttptype.Event)
	ReportRulePolicy(containerID, ruleId, allowedProcess string, allowedContainer bool)
	ReportIdentifiedCallStack(containerID string, callStack *v1beta1.IdentifiedCallStack)
	ReportSymlinkEvent(containerID string, event *tracersymlinktype.Event)
	ReportHardlinkEvent(containerID string, event *tracerhardlinktype.Event)
	ReportNetworkEvent(containerID string, event *utils.DatasourceEvent)
	ReportSyscalls(containerID string, syscalls []string)
	ReportDroppedEvent(containerID string)
	RegisterForContainerEndOfLife(notificationChannel chan *containercollection.Container)
	OnQueueError(profile *v1beta1.ContainerProfile, containerID string, err error)
}

type Enricher interface {
	EnrichEvent(containerID string, event utils.EnrichEvent, callID string)
}
