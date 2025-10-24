package containerprofilemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ContainerProfileManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ReportCapability(containerID, capability string)
	ReportFileExec(containerID string, event utils.ExecEvent)
	ReportFileOpen(containerID string, event utils.OpenEvent)
	ReportHTTPEvent(containerID string, event utils.HttpEvent)
	ReportRulePolicy(containerID, ruleId, allowedProcess string, allowedContainer bool)
	ReportIdentifiedCallStack(containerID string, callStack *v1beta1.IdentifiedCallStack)
	ReportSymlinkEvent(containerID string, event utils.LinkEvent)
	ReportHardlinkEvent(containerID string, event utils.LinkEvent)
	ReportNetworkEvent(containerID string, event utils.NetworkEvent)
	ReportSyscall(containerID string, syscall string)
	ReportDroppedEvent(containerID string)
	RegisterForContainerEndOfLife(notificationChannel chan *containercollection.Container)
	OnQueueError(profile *v1beta1.ContainerProfile, containerID string, err error)
}

type Enricher interface {
	EnrichEvent(containerID string, event utils.EnrichEvent, callID string)
}
