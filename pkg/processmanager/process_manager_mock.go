package processmanager

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/utils"
)

type ProcessManagerMock struct {
}

var _ ProcessManagerClient = (*ProcessManagerMock)(nil)

func CreateProcessManagerMock() *ProcessManagerMock {
	return &ProcessManagerMock{}
}

func (p *ProcessManagerMock) GetProcessTreeForPID(containerID string, pid int) (apitypes.Process, error) {
	return apitypes.Process{}, nil
}

func (p *ProcessManagerMock) PopulateInitialProcesses() error {
	return nil
}

func (p *ProcessManagerMock) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	// no-op
}

func (p *ProcessManagerMock) ContainerCallback(notif containercollection.PubSubEvent) {
	// no-op
}
