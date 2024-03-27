package networkmanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
)

type NetworkManagerMock struct {
}

var _ NetworkManagerClient = (*NetworkManagerMock)(nil)

func CreateNetworkManagerMock() *NetworkManagerMock {
	return &NetworkManagerMock{}
}

func (am *NetworkManagerMock) ContainerCallback(notif containercollection.PubSubEvent) {

}

func (am *NetworkManagerMock) ReportNetworkEvent(containerID string, event tracernetworktype.Event) {
}
