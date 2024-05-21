package relevancymanager

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	corev1 "k8s.io/api/core/v1"
)

type RelevancyManagerMock struct {
}

var _ RelevancyManagerClient = (*RelevancyManagerMock)(nil)

func CreateRelevancyManagerMock() *RelevancyManagerMock {
	return &RelevancyManagerMock{}
}

func (r RelevancyManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}

func (r RelevancyManagerMock) ReportFileExec(_, _, _ string) {
	// noop
}

func (r RelevancyManagerMock) ReportFileOpen(_, _, _ string) {
	// noop
}

func (r RelevancyManagerMock) ContainerReachedMaxTime(_ string) {
	// noop
}

func (r RelevancyManagerMock) HasRelevancyCalculating(_ *corev1.Pod) bool {
	return false
}
