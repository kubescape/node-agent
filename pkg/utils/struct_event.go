package utils

import (
	"net"
	"net/http"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

type StructEvent struct {
	Addresses            []string                `json:"addresses,omitempty" yaml:"addresses,omitempty"`
	Args                 []string                `json:"args,omitempty" yaml:"args,omitempty"`
	AttrSize             uint32                  `json:"attrSize,omitempty" yaml:"attrSize,omitempty"`
	Buf                  []byte                  `json:"buf,omitempty" yaml:"buf,omitempty"`
	CapName              string                  `json:"capName,omitempty" yaml:"capName,omitempty"`
	Cmd                  uint32                  `json:"cmd,omitempty" yaml:"cmd,omitempty"`
	Comm                 string                  `json:"comm,omitempty" yaml:"comm,omitempty"`
	Container            string                  `json:"container,omitempty" yaml:"container,omitempty"`
	ContainerID          string                  `json:"containerId,omitempty" yaml:"containerId,omitempty"`
	ContainerImage       string                  `json:"containerImage,omitempty" yaml:"containerImage,omitempty"`
	ContainerImageDigest string                  `json:"containerImageDigest,omitempty" yaml:"containerImageDigest,omitempty"`
	Cwd                  string                  `json:"cwd,omitempty" yaml:"cwd,omitempty"`
	DNSName              string                  `json:"dnsName,omitempty" yaml:"dnsName,omitempty"`
	Dir                  bool                    `json:"dir,omitempty" yaml:"dir,omitempty"`
	Direction            consts.NetworkDirection `json:"direction,omitempty" yaml:"direction,omitempty"`
	DstEndpoint          types.L3Endpoint        `json:"dstEndpoint,omitempty" yaml:"dstEndpoint,omitempty"`
	DstIP                string                  `json:"dstIP,omitempty" yaml:"dstIP,omitempty"`
	DstPort              uint16                  `json:"dstPort,omitempty" yaml:"dstPort,omitempty"`
	Error                int64                   `json:"error,omitempty" yaml:"error,omitempty"`
	EventType            EventType               `json:"eventType,omitempty" yaml:"eventType,omitempty"`
	ExePath              string                  `json:"exePath,omitempty" yaml:"exePath,omitempty"`
	ExitCode             uint32                  `json:"exitCode,omitempty" yaml:"exitCode,omitempty"`
	Extra                interface{}             `json:"extra,omitempty" yaml:"extra,omitempty"`
	Flags                []string                `json:"flags,omitempty" yaml:"flags,omitempty"`
	FlagsRaw             uint32                  `json:"flagsRaw,omitempty" yaml:"flagsRaw,omitempty"`
	FullPath             string                  `json:"fullPath,omitempty" yaml:"fullPath,omitempty"`
	FullPathTracing      bool                    `json:"fullPathTracing,omitempty" yaml:"fullPathTracing,omitempty"`
	Gid                  uint32                  `json:"gid,omitempty" yaml:"gid,omitempty"`
	HostNetwork          bool                    `json:"hostNetwork,omitempty" yaml:"hostNetwork,omitempty"`
	ID                   string                  `json:"id,omitempty" yaml:"id,omitempty"`
	Identifier           string                  `json:"identifier,omitempty" yaml:"identifier,omitempty"`
	Internal             bool                    `json:"internal,omitempty" yaml:"internal,omitempty"`
	Module               string                  `json:"module,omitempty" yaml:"module,omitempty"`
	MountNsID            uint64                  `json:"mountNsID,omitempty" yaml:"mountNsID,omitempty"`
	Namespace            string                  `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	NewPath              string                  `json:"newPath,omitempty" yaml:"newPath,omitempty"`
	NumAnswers           int                     `json:"numAnswers,omitempty" yaml:"numAnswers,omitempty"`
	OldPath              string                  `json:"oldPath,omitempty" yaml:"oldPath,omitempty"`
	Opcode               int                     `json:"opcode,omitempty" yaml:"opcode,omitempty"`
	PID64                uint64                  `json:"pid64,omitempty" yaml:"pid64,omitempty"`
	Path                 string                  `json:"path,omitempty" yaml:"path,omitempty"`
	Pcomm                string                  `json:"pcomm,omitempty" yaml:"pcomm,omitempty"`
	Pid                  uint32                  `json:"pid,omitempty" yaml:"pid,omitempty"`
	PktType              string                  `json:"pktType,omitempty" yaml:"pktType,omitempty"`
	Pod                  string                  `json:"pod,omitempty" yaml:"pod,omitempty"`
	PodHostIP            string                  `json:"podHostIP,omitempty" yaml:"podHostIP,omitempty"`
	PodLabels            map[string]string       `json:"podLabels,omitempty" yaml:"podLabels,omitempty"`
	Ppid                 uint32                  `json:"ppid,omitempty" yaml:"ppid,omitempty"`
	Proto                string                  `json:"proto,omitempty" yaml:"proto,omitempty"`
	Ptid                 uint64                  `json:"ptid,omitempty" yaml:"ptid,omitempty"`
	PtraceRequest        int                     `json:"ptraceRequest,omitempty" yaml:"ptraceRequest,omitempty"`
	PupperLayer          bool                    `json:"pupperLayer,omitempty" yaml:"pupperLayer,omitempty"`
	Qr                   DNSPktType              `json:"qr,omitempty" yaml:"qr,omitempty"`
	Request              *http.Request           `json:"request,omitempty" yaml:"request,omitempty"`
	Response             *http.Response          `json:"response,omitempty" yaml:"response,omitempty"`
	Signal               uint32                  `json:"signal,omitempty" yaml:"signal,omitempty"`
	SockFd               uint32                  `json:"sockFd,omitempty" yaml:"sockFd,omitempty"`
	SocketInode          uint64                  `json:"socketInode,omitempty" yaml:"socketInode,omitempty"`
	SrcIP                string                  `json:"srcIP,omitempty" yaml:"srcIP,omitempty"`
	SrcPort              uint16                  `json:"srcPort,omitempty" yaml:"srcPort,omitempty"`
	StatusCode           int                     `json:"statusCode,omitempty" yaml:"statusCode,omitempty"`
	Syscall              string                  `json:"syscall,omitempty" yaml:"syscall,omitempty"`
	Syscalls             []byte                  `json:"syscalls,omitempty" yaml:"syscalls,omitempty"`
	Tid                  uint64                  `json:"tid,omitempty" yaml:"tid,omitempty"`
	Timestamp            int64                   `json:"timestamp,omitempty" yaml:"timestamp,omitempty"`
	Type                 HTTPDataType            `json:"type,omitempty" yaml:"type,omitempty"`
	Uid                  uint32                  `json:"uid,omitempty" yaml:"uid,omitempty"`
	UpperLayer           bool                    `json:"upperLayer,omitempty" yaml:"upperLayer,omitempty"`
	UserData             int                     `json:"userData,omitempty" yaml:"userData,omitempty"`
}

var _ BpfEvent = (*StructEvent)(nil)
var _ CapabilitiesEvent = (*StructEvent)(nil)
var _ DNSEvent = (*StructEvent)(nil)
var _ ExecEvent = (*StructEvent)(nil)
var _ ExitEvent = (*StructEvent)(nil)
var _ ForkEvent = (*StructEvent)(nil)
var _ HttpEvent = (*StructEvent)(nil)
var _ HttpRawEvent = (*StructEvent)(nil)
var _ IOUring = (*StructEvent)(nil)
var _ KmodEvent = (*StructEvent)(nil)
var _ LinkEvent = (*StructEvent)(nil)
var _ NetworkEvent = (*StructEvent)(nil)
var _ OpenEvent = (*StructEvent)(nil)
var _ SshEvent = (*StructEvent)(nil)
var _ SyscallEvent = (*StructEvent)(nil)
var _ UnshareEvent = (*StructEvent)(nil)

func (e *StructEvent) GetAttrSize() uint32 {
	switch e.EventType {
	case BpfEventType:
		return e.AttrSize
	default:
		logger.L().Warning("GetAttrSize not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetAddresses() []string {
	switch e.EventType {
	case DnsEventType:
		return e.Addresses
	default:
		logger.L().Warning("GetAddresses not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *StructEvent) GetArgs() []string {
	switch e.EventType {
	case ExecveEventType:
		return e.Args
	default:
		logger.L().Warning("GetArgs not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *StructEvent) GetBuf() []byte {
	switch e.EventType {
	case HTTPEventType:
		return e.Buf
	default:
		logger.L().Warning("GetBuf not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *StructEvent) GetCapability() string {
	switch e.EventType {
	case CapabilitiesEventType:
		return e.CapName
	default:
		logger.L().Warning("GetCapability not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetCmd() uint32 {
	switch e.EventType {
	case BpfEventType:
		return e.Cmd
	default:
		logger.L().Warning("GetCmd not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetComm() string {
	switch e.EventType {
	case SyscallEventType:
		return e.Comm
	default:
		return e.Comm
	}
}

func (e *StructEvent) GetContainer() string {
	return e.Container
}

func (e *StructEvent) GetContainerID() string {
	return e.ContainerID
}

func (e *StructEvent) GetContainerImage() string {
	return e.ContainerImage
}

func (e *StructEvent) GetContainerImageDigest() string {
	return e.ContainerImageDigest
}

func (e *StructEvent) GetCwd() string {
	switch e.EventType {
	case ExecveEventType, DnsEventType:
		return e.Cwd
	default:
		logger.L().Warning("GetCwd not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetDirection() consts.NetworkDirection {
	return e.Direction
}

func (e *StructEvent) GetDNSName() string {
	switch e.EventType {
	case DnsEventType:
		return e.DNSName
	default:
		logger.L().Warning("GetDNSName not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetDstEndpoint() types.L4Endpoint {
	switch e.EventType {
	case NetworkEventType:
		return types.L4Endpoint{
			L3Endpoint: e.DstEndpoint,
		}
	default:
		logger.L().Warning("GetDstEndpoint not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return types.L4Endpoint{}
	}
}

func (e *StructEvent) GetDstIP() string {
	switch e.EventType {
	case DnsEventType, HTTPEventType, SSHEventType:
		return e.DstIP
	}
	return ""
}

func (e *StructEvent) GetDstPort() uint16 {
	switch e.EventType {
	case NetworkEventType:
		return e.DstPort
	case DnsEventType, HTTPEventType, SSHEventType:
		return e.DstPort
	default:
		logger.L().Warning("GetDstPort not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetError() int64 {
	return e.Error
}

func (e *StructEvent) GetEventType() EventType {
	return e.EventType
}

func (e *StructEvent) GetExePath() string {
	switch e.EventType {
	case DnsEventType, ExecveEventType, ForkEventType, PtraceEventType, RandomXEventType, KmodEventType, UnshareEventType, BpfEventType:
		return NormalizePath(e.ExePath)
	default:
		logger.L().Warning("GetExePath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetExitCode() uint32 {
	switch e.EventType {
	case ExitEventType:
		return e.ExitCode
	default:
		logger.L().Warning("GetExitCode not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetExtra() interface{} {
	return e.Extra
}

func (e *StructEvent) GetFlags() []string {
	switch e.EventType {
	case OpenEventType:
		return e.Flags
	default:
		logger.L().Warning("GetFlags not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *StructEvent) GetFlagsRaw() uint32 {
	switch e.EventType {
	case OpenEventType:
		return e.FlagsRaw
	default:
		logger.L().Warning("GetFlagsRaw not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetFullPath() string {
	switch e.EventType {
	case OpenEventType:
		return NormalizePath(e.FullPath)
	default:
		logger.L().Warning("GetFullPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetGid() *uint32 {
	switch e.EventType {
	case CapabilitiesEventType, DnsEventType, ExecveEventType, ExitEventType, ForkEventType, HTTPEventType, NetworkEventType, OpenEventType, KmodEventType, UnshareEventType, BpfEventType:
		return &e.Gid
	default:
		logger.L().Warning("GetGid not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *StructEvent) GetHostNetwork() bool {
	return e.HostNetwork
}

func (e *StructEvent) GetIdentifier() string {
	switch e.EventType {
	case IoUringEventType:
		return e.Identifier
	default:
		logger.L().Warning("GetIdentifier not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetInternal() bool {
	return e.Internal
}

func (e *StructEvent) GetModule() string {
	switch e.EventType {
	case KmodEventType:
		return e.Module
	default:
		logger.L().Warning("GetModule not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetMountNsID() uint64 {
	return e.MountNsID
}

func (e *StructEvent) GetNamespace() string {
	return e.Namespace
}

func (e *StructEvent) GetNewPath() string {
	switch e.EventType {
	case HardlinkEventType, SymlinkEventType:
		return NormalizePath(e.NewPath)
	default:
		logger.L().Warning("GetNewPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetNumAnswers() int {
	switch e.EventType {
	case DnsEventType:
		return e.NumAnswers
	default:
		logger.L().Warning("GetNumAnswers not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetOldPath() string {
	switch e.EventType {
	case HardlinkEventType, SymlinkEventType:
		return NormalizePath(e.OldPath)
	default:
		logger.L().Warning("GetOldPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetOpcode() int {
	switch e.EventType {
	case IoUringEventType:
		return e.Opcode
	default:
		logger.L().Warning("GetOpcode not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetOtherIp() string {
	switch e.EventType {
	case HTTPEventType:
		if e.Direction == consts.Inbound {
			return e.GetSrcIP()
		}
		return e.GetDstIP()
	default:
		logger.L().Warning("GetOtherIp not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetPath() string {
	if e.FullPathTracing {
		return e.GetFullPath()
	}
	switch e.EventType {
	case OpenEventType:
		return NormalizePath(e.Path)
	default:
		logger.L().Warning("GetPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetPcomm() string {
	return e.Pcomm
}

func (e *StructEvent) GetPID() uint32 {
	switch e.EventType {
	case ForkEventType:
		return e.Pid
	case ExitEventType:
		return e.Pid
	case SyscallEventType:
		return e.Pid
	default:
		return e.Pid
	}
}

// GetPID64 is a special implementation for stack trace events.
func (e *StructEvent) GetPID64() uint64 {
	switch e.EventType {
	case ExecveEventType:
		return e.PID64
	case OpenEventType, ExitEventType, ForkEventType, HardlinkEventType, SymlinkEventType:
		return e.PID64
	default:
		logger.L().Warning("GetPID64 not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetPktType() string {
	return e.PktType
}

func (e *StructEvent) GetPod() string {
	return e.Pod
}

func (e *StructEvent) GetPodHostIP() string {
	switch e.EventType {
	case NetworkEventType:
		return e.PodHostIP
	default:
		logger.L().Warning("GetPodHostIP not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetPodLabels() map[string]string {
	return e.PodLabels
}

func (e *StructEvent) GetPpid() uint32 {
	switch e.EventType {
	case ForkEventType:
		return e.Ppid
	case ExitEventType:
		return e.Ppid
	default:
		return e.Ppid
	}
}

func (e *StructEvent) GetProto() string {
	switch e.EventType {
	case DnsEventType:
		return e.Proto
	case NetworkEventType:
		return e.Proto
	default:
		logger.L().Warning("GetProto not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetPtid() uint64 {
	return e.Ptid
}

func (e *StructEvent) GetPupperLayer() bool {
	switch e.EventType {
	case ExecveEventType:
		return e.PupperLayer
	default:
		logger.L().Warning("GetPupperLayer not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
}

func (e *StructEvent) GetQr() DNSPktType {
	switch e.EventType {
	case DnsEventType:
		return e.Qr
	default:
		logger.L().Warning("GetQr not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetRequest() *http.Request {
	return e.Request
}

func (e *StructEvent) GetResponse() *http.Response {
	return e.Response
}

func (e *StructEvent) GetSignal() uint32 {
	switch e.EventType {
	case ExitEventType:
		return e.Signal
	default:
		logger.L().Warning("GetSignal not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetSocketInode() uint64 {
	switch e.EventType {
	case HTTPEventType:
		return e.SocketInode
	default:
		logger.L().Warning("GetSocketInode not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetSockFd() uint32 {
	switch e.EventType {
	case HTTPEventType:
		return e.SockFd
	default:
		logger.L().Warning("GetSockFd not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetSrcIP() string {
	switch e.EventType {
	case DnsEventType, HTTPEventType, SSHEventType:
		return e.SrcIP
	}
	return ""
}

func (e *StructEvent) GetSrcPort() uint16 {
	switch e.EventType {
	case DnsEventType, HTTPEventType, SSHEventType:
		return e.SrcPort
	default:
		logger.L().Warning("GetSrcPort not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetSyscall() string {
	switch e.EventType {
	case CapabilitiesEventType:
		return e.Syscall
	case HTTPEventType:
		return e.Syscall
	case SyscallEventType:
		return e.Syscall
	case KmodEventType:
		return e.Syscall
	default:
		logger.L().Warning("GetSyscall not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetSyscalls() []byte {
	switch e.EventType {
	case SyscallEventType:
		return e.Syscalls
	default:
		logger.L().Warning("GetSyscalls not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *StructEvent) GetTid() uint64 {
	return e.Tid
}

func (e *StructEvent) GetTimestamp() types.Time {
	switch e.EventType {
	case SyscallEventType:
		return types.Time(time.Now().UnixNano())
	default:
		return types.Time(e.Timestamp)
	}
}

func (e *StructEvent) GetType() HTTPDataType {
	switch e.EventType {
	case HTTPEventType:
		return e.Type
	default:
		logger.L().Warning("GetType not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetUid() *uint32 {
	switch e.EventType {
	case CapabilitiesEventType, DnsEventType, ExecveEventType, ExitEventType, ForkEventType, HTTPEventType, NetworkEventType, OpenEventType, KmodEventType, UnshareEventType, BpfEventType:
		return &e.Uid
	default:
		logger.L().Warning("GetUid not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *StructEvent) GetUpperLayer() bool {
	switch e.EventType {
	case ExecveEventType, SymlinkEventType, HardlinkEventType, ExitEventType, RandomXEventType, KmodEventType, UnshareEventType, BpfEventType:
		return e.UpperLayer
	default:
		logger.L().Warning("GetUpperLayer not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
}

func (e *StructEvent) HasDroppedEvents() bool {
	return false
}

func (e *StructEvent) IsDir() bool {
	switch e.EventType {
	case OpenEventType:
		return e.Dir
	default:
		logger.L().Warning("IsDir not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
}

func (e *StructEvent) MakeHttpEvent(request *http.Request, direction consts.NetworkDirection) HttpEvent {
	event := *e
	event.Request = request
	event.Direction = direction
	event.Internal = func() bool { ip := net.ParseIP(e.GetOtherIp()); return ip != nil && ip.IsPrivate() }()
	return &event
}

func (e *StructEvent) Release() {}

func (e *StructEvent) SetExtra(extra interface{}) {
	e.Extra = extra
}

func (e *StructEvent) SetResponse(response *http.Response) {
	e.Response = response
}

// ECS-specific methods - implementing EnrichEvent interface
func (e *StructEvent) GetEcsClusterName() string {
	return ""
}

func (e *StructEvent) GetEcsClusterARN() string {
	return ""
}

func (e *StructEvent) GetEcsTaskARN() string {
	return ""
}

func (e *StructEvent) GetEcsTaskFamily() string {
	return ""
}

func (e *StructEvent) GetEcsTaskDefinitionARN() string {
	return ""
}

func (e *StructEvent) GetEcsServiceName() string {
	return ""
}

func (e *StructEvent) GetEcsContainerName() string {
	return ""
}

func (e *StructEvent) GetEcsContainerARN() string {
	return ""
}

func (e *StructEvent) GetEcsContainerInstance() string {
	return ""
}

func (e *StructEvent) GetEcsAvailabilityZone() string {
	return ""
}

func (e *StructEvent) GetEcsLaunchType() string {
	return ""
}
