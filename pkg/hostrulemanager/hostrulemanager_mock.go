package hostrulemanager

import "github.com/kubescape/node-agent/pkg/utils"

type HostRuleManagerMock struct {
}

var _ HostRuleManagerClient = (*HostRuleManagerMock)(nil)

func CreateHostRuleManagerMock() *HostRuleManagerMock {
	return &HostRuleManagerMock{}
}

func (r *HostRuleManagerMock) ReportEvent(_ utils.EventType, _ utils.K8sEvent) {
	// noop
}

func (r *HostRuleManagerMock) RegisterPeekFunc(_ func(mntns uint64) ([]string, error)) {
	// noop
}
