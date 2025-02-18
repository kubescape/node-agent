package hostnetworksensor

import "github.com/kubescape/node-agent/pkg/utils"

type HostNetworkSensorClient interface {
	ReportEvent(eventType utils.EventType, event utils.K8sEvent)
}
