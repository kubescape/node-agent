package hostnetworksensor

import "github.com/kubescape/node-agent/pkg/utils"

type HostNetworkSensorMock struct {
}

var _ HostNetworkSensorClient = (*HostNetworkSensorMock)(nil)

func CreateHostNetworkSensorMock() *HostNetworkSensorMock {
	return &HostNetworkSensorMock{}
}

func (r HostNetworkSensorMock) ReportEvent(_ utils.EventType, _ utils.K8sEvent) {
	// noop
}
