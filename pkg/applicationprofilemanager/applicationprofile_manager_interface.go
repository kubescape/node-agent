package applicationprofilemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type ApplicationProfileManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	RegisterPeekFunc(peek func(mntns uint64) ([]string, error))
	ReportCapability(k8sContainerID, capability string)
	ReportFileExec(k8sContainerID string, event events.ExecEvent)
	ReportFileOpen(k8sContainerID string, event events.OpenEvent)
	ReportHTTPEvent(k8sContainerID string, event *tracerhttptype.Event)
	ReportRulePolicy(k8sContainerID, ruleId, allowedProcess string, allowedContainer bool)
	ReportIdentifiedCallStack(k8sContainerID string, callStack *v1beta1.IdentifiedCallStack)
	ReportDroppedEvent(k8sContainerID string)
	ContainerReachedMaxTime(containerID string)
}

type Enricher interface {
	EnrichEvent(k8sContainerID string, event utils.EnrichEvent, callID string)
}
