package relevancymanager

import containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"

type RelevancyManagerMock struct {
}

var _ RelevancyManagerClient = (*RelevancyManagerMock)(nil)

func CreateRelevancyManagerMock() *RelevancyManagerMock {
	return &RelevancyManagerMock{}
}

func (r RelevancyManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}

func (r RelevancyManagerMock) ReportFileAccess(_, _ string) {
	// noop
}
