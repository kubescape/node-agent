package networkstream

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/utils"
)

type NetworkStreamMock struct {
}

var _ NetworkStreamClient = (*NetworkStreamMock)(nil)

func CreateNetworkStreamMock() *NetworkStreamMock {
	return &NetworkStreamMock{}
}

func (r NetworkStreamMock) ReportEvent(_ utils.EventType, _ utils.K8sEvent) {
	// noop
}

func (r NetworkStreamMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}

func (r NetworkStreamMock) Start() {
	// noop
}
