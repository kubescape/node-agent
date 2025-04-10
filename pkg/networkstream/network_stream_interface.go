package networkstream

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/utils"
)

type NetworkStreamClient interface {
	ContainerCallback(notif containercollection.PubSubEvent)
	ReportEvent(eventType utils.EventType, event utils.K8sEvent)

	Start()
}
