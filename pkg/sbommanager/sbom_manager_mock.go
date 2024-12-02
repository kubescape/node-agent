package sbommanager

import containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"

type SbomManagerMock struct{}

var _ SbomManagerClient = (*SbomManagerMock)(nil)

func CreateSbomManagerMock() *SbomManagerMock {
	return &SbomManagerMock{}
}

func (s SbomManagerMock) ContainerCallback(_ containercollection.PubSubEvent) {
	// noop
}
