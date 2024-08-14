package v1

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
)

type NetworkManagerMock struct {
}

var _ NetworkManagerClient = (*NetworkManagerMock)(nil)

func (am *NetworkManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {

}

func (am *NetworkManagerMock) ReportNetworkEvent(_ string, _ tracernetworktype.Event) {
	// noop
}

func (am *NetworkManagerMock) ReportDroppedEvent(_ string, _ tracernetworktype.Event) {
	// noop
}
func (am *NetworkManagerMock) ContainerReachedMaxTime(_ string) {
	// noop
}
