package rulemanager

import (
	"github.com/kubescape/node-agent/pkg/utils"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	v1 "k8s.io/api/core/v1"
)

type RuleManagerMock struct {
}

var _ RuleManagerClient = (*RuleManagerMock)(nil)

func CreateRuleManagerMock() *RuleManagerMock {
	return &RuleManagerMock{}
}

func (r *RuleManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}

func (r *RuleManagerMock) RegisterPeekFunc(_ func(mntns uint64) ([]string, error)) {
	// noop
}

func (r *RuleManagerMock) ReportEvent(_ utils.EventType, _ utils.K8sEvent) {
	// noop
}

func (r *RuleManagerMock) HasApplicableRuleBindings(_, _ string) bool {
	return false
}

func (r *RuleManagerMock) HasFinalApplicationProfile(_ *v1.Pod) bool {
	return false
}

func (r *RuleManagerMock) IsContainerMonitored(_ string) bool {
	return false
}

func (r *RuleManagerMock) IsPodMonitored(_, _ string) bool {
	return false
}
