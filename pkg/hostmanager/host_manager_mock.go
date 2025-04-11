package hostmanager

import "context"

type HostManagerMock struct{}

var _ HostManagerClient = (*HostManagerMock)(nil)

func CreateHostManagerMock() *HostManagerMock {
	return &HostManagerMock{}
}

func (h HostManagerMock) Start(_ context.Context) {}
