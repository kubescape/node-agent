package utils

import (
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type StructEvent struct {
	Addresses            []string
	Container            string
	ContainerID          string
	ContainerImage       string
	ContainerImageDigest string
	DNSName              string
	Extra                interface{}
	HostNetwork          bool
	ID                   string
	Namespace            string
	Pid                  uint32
	Pod                  string
	Timestamp            int64
}

var _ EnrichEvent = (*StructEvent)(nil)
var _ DNSEvent = (*StructEvent)(nil)
var _ ContainerEvent = (*StructEvent)(nil)

func (e StructEvent) GetAddresses() []string {
	return e.Addresses
}

func (e StructEvent) GetContainer() string {
	return e.Container
}

func (e StructEvent) GetContainerID() string {
	return e.ContainerID
}

func (e StructEvent) GetContainerImage() string {
	return e.ContainerImage
}

func (e StructEvent) GetContainerImageDigest() string {
	return e.ContainerImageDigest
}

func (e StructEvent) GetDNSName() string {
	return e.DNSName
}

func (e StructEvent) GetExtra() interface{} {
	return e.Extra
}

func (e StructEvent) GetHostNetwork() bool {
	return e.HostNetwork
}

func (e StructEvent) GetNamespace() string {
	return e.Namespace
}

func (e StructEvent) GetPID() uint32 {
	return e.Pid
}

func (e StructEvent) GetPod() string {
	return e.Pod
}

func (e StructEvent) GetTimestamp() eventtypes.Time {
	return eventtypes.Time(e.Timestamp)
}

func (e StructEvent) SetExtra(extra interface{}) {
	e.Extra = extra
}
