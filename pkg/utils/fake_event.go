package utils

import (
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type FakeEvent struct {
	Addresses   []string
	ContainerID string
	DNSName     string
	Pid         uint32
}

func (f FakeEvent) GetAddresses() []string {
	return f.Addresses
}

func (f FakeEvent) GetContainer() string {
	//TODO implement me
	panic("implement me")
}

func (f FakeEvent) GetContainerID() string {
	return f.ContainerID
}

func (f FakeEvent) GetContainerImage() string {
	//TODO implement me
	panic("implement me")
}

func (f FakeEvent) GetContainerImageDigest() string {
	//TODO implement me
	panic("implement me")
}

func (f FakeEvent) GetDNSName() string {
	return f.DNSName
}

func (f FakeEvent) GetHostNetwork() bool {
	//TODO implement me
	panic("implement me")
}

func (f FakeEvent) GetNamespace() string {
	//TODO implement me
	panic("implement me")
}

func (f FakeEvent) GetPid() uint32 {
	return f.Pid
}

func (f FakeEvent) GetPod() string {
	//TODO implement me
	panic("implement me")
}

func (f FakeEvent) GetTimestamp() eventtypes.Time {
	//TODO implement me
	panic("implement me")
}

var _ K8sEvent = (*FakeEvent)(nil)
