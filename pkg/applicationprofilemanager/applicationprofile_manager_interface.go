package applicationprofilemanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
)

type ApplicationProfileManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	RegisterPeekFunc(peek func(mntns uint64) ([]string, error))
	ReportCapability(k8sContainerID, capability string)
	ReportFileExec(k8sContainerID, path string, args []string)
	ReportFileOpen(k8sContainerID, path string, flags []string)
	ReportHTTPEvent(k8sContainerID, event *tracerhttptype.Event)
	ReportDroppedEvent(k8sContainerID string)
	ContainerReachedMaxTime(containerID string)
}
