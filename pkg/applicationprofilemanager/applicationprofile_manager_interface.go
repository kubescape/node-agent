package applicationprofilemanager

import containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"

type ApplicationProfileManagerClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	RegisterPeekFunc(peek func(mntns uint64) ([]string, error))
	ReportCapability(k8sContainerID, capability string)
	ReportFileExec(k8sContainerID, path string, args []string)
	ReportFileOpen(k8sContainerID, path string, flags []string)
}
