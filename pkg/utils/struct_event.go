package utils

import (
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type StructEvent struct {
	Addresses            []string
	Args                 []string
	CapName              string
	Comm                 string
	Container            string
	ContainerID          string
	ContainerImage       string
	ContainerImageDigest string
	Cwd                  string
	DNSName              string
	DstEndpoint          eventtypes.L3Endpoint
	Error                int64
	EventType            EventType
	ExePath              string
	Extra                interface{}
	Flags                []string
	FlagsRaw             uint32
	FullPath             string
	Gid                  uint32
	HostNetwork          bool
	ID                   string
	Namespace            string
	Path                 string
	Pcomm                string
	Pid                  uint32
	PktType              string
	Pod                  string
	PodLabels            map[string]string
	Port                 uint16
	Ppid                 uint32
	Proto                string
	PupperLayer          bool
	Qr                   DNSPktType
	Syscall              string
	Timestamp            int64
	Uid                  uint32
	UpperLayer           bool
}

var _ EverythingEvent = (*StructEvent)(nil)

func (e StructEvent) GetAddresses() []string {
	return e.Addresses
}

func (e StructEvent) GetArgs() []string {
	return e.Args
}

func (e StructEvent) GetCapability() string {
	return e.CapName
}

func (e StructEvent) GetComm() string {
	return e.Comm
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

func (e StructEvent) GetCwd() string {
	return e.Cwd
}

func (e StructEvent) GetDNSName() string {
	return e.DNSName
}

func (e StructEvent) GetDstEndpoint() eventtypes.L4Endpoint {
	return eventtypes.L4Endpoint{
		L3Endpoint: e.DstEndpoint,
	}
}

func (e StructEvent) GetDstPort() uint16 {
	return e.Port
}

func (e StructEvent) GetError() int64 {
	return e.Error
}

func (e StructEvent) GetEventType() EventType {
	return e.EventType
}

func (e StructEvent) GetExePath() string {
	return e.ExePath
}

func (e StructEvent) GetExecArgsFromEvent() []string {
	return e.Args
}

func (e StructEvent) GetExecFullPathFromEvent() string {
	return e.FullPath
}

func (e StructEvent) GetExecPathFromEvent() string {
	return e.ExePath
}

func (e StructEvent) GetExtra() interface{} {
	return e.Extra
}

func (e StructEvent) GetFlags() []string {
	return e.Flags
}

func (e StructEvent) GetFlagsRaw() uint32 {
	return e.FlagsRaw
}

func (e StructEvent) GetGid() *uint32 {
	return &e.Gid
}

func (e StructEvent) GetHostFilePathFromEvent(_ uint32) (string, error) {
	return "TODO implement", nil
}

func (e StructEvent) GetHostNetwork() bool {
	return e.HostNetwork
}

func (e StructEvent) GetNamespace() string {
	return e.Namespace
}

func (e StructEvent) GetNumAnswers() int {
	return 0
}

func (e StructEvent) GetPath() string {
	return e.Path
}

func (e StructEvent) GetPcomm() string {
	return e.Pcomm
}

func (e StructEvent) GetPID() uint32 {
	return e.Pid
}

func (e StructEvent) GetPktType() string {
	return e.PktType
}

func (e StructEvent) GetPod() string {
	return e.Pod
}

func (e StructEvent) GetPodHostIP() string {
	return "TODO implement"
}

func (e StructEvent) GetPodLabels() map[string]string {
	return e.PodLabels
}

func (e StructEvent) GetPort() uint16 {
	return e.Port
}

func (e StructEvent) GetPpid() uint32 {
	return e.Ppid
}

func (e StructEvent) GetProto() string {
	return e.Proto
}

func (e StructEvent) GetPupperLayer() bool {
	return e.PupperLayer
}

func (e StructEvent) GetQr() DNSPktType {
	return e.Qr
}

func (e StructEvent) GetSyscall() string {
	return e.Syscall
}

func (e StructEvent) GetSyscalls() []string {
	return []string{e.Syscall}
}

func (e StructEvent) GetTimestamp() eventtypes.Time {
	return eventtypes.Time(e.Timestamp)
}

func (e StructEvent) GetUid() *uint32 {
	return &e.Uid
}

func (e StructEvent) GetUpperLayer() bool {
	return e.UpperLayer
}

func (e StructEvent) IsDir() bool {
	return false
}

func (e StructEvent) SetExtra(extra interface{}) {
	e.Extra = extra
}
