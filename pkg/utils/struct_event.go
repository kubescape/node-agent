package utils

import (
	"net/http"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

type StructEvent struct {
	Addresses            []string
	Args                 []string
	Buf                  []byte
	CapName              string
	Comm                 string
	Container            string
	ContainerID          string
	ContainerImage       string
	ContainerImageDigest string
	Cwd                  string
	DNSName              string
	Dir                  bool
	Direction            consts.NetworkDirection
	DstEndpoint          types.L3Endpoint
	DstIP                string
	DstPort              uint16
	Error                int64
	EventType            EventType
	ExePath              string
	Extra                interface{}
	Flags                []string
	FlagsRaw             uint32
	Gid                  uint32
	HostNetwork          bool
	ID                   string
	Identifier           string
	Internal             bool
	Namespace            string
	NewPath              string
	NumAnswers           int
	OldPath              string
	Opcode               int
	Path                 string
	Pcomm                string
	Pid                  uint32
	PktType              string
	Pod                  string
	PodHostIP            string
	PodLabels            map[string]string
	Ppid                 uint32
	Proto                string
	PtraceRequest        int
	PupperLayer          bool
	Qr                   DNSPktType
	Request              *http.Request
	Response             *http.Response
	SockFd               uint32
	SocketInode          uint64
	SrcIP                string
	SrcPort              uint16
	StatusCode           int
	Syscall              string
	Timestamp            int64
	Type                 HTTPDataType
	Uid                  uint32
	UpperLayer           bool
	UserData             int
}

var _ CapabilitiesEvent = (*DatasourceEvent)(nil)
var _ DNSEvent = (*DatasourceEvent)(nil)
var _ ExecEvent = (*DatasourceEvent)(nil)
var _ HttpEvent = (*StructEvent)(nil)
var _ HttpRawEvent = (*DatasourceEvent)(nil)
var _ IOUring = (*DatasourceEvent)(nil)
var _ LinkEvent = (*DatasourceEvent)(nil)
var _ NetworkEvent = (*DatasourceEvent)(nil)
var _ OpenEvent = (*DatasourceEvent)(nil)
var _ SshEvent = (*DatasourceEvent)(nil)
var _ SyscallEvent = (*DatasourceEvent)(nil)

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

func (e *StructEvent) GetComm() string {
	return e.Comm
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
	case ExecveEventType:
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
	case SSHEventType:
		return e.DstIP
	}
	return ""
}

func (e *StructEvent) GetDstPort() uint16 {
	switch e.EventType {
	case NetworkEventType:
		return e.DstPort
	case SSHEventType:
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
	case ExecveEventType, ForkEventType, PtraceEventType, RandomXEventType:
		return e.ExePath
	default:
		logger.L().Warning("GetExePath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
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

func (e *StructEvent) GetGid() *uint32 {
	switch e.EventType {
	case CapabilitiesEventType, ExecveEventType, ExitEventType, ForkEventType, HTTPEventType:
		return &e.Gid
	case OpenEventType:
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

func (e *StructEvent) GetNamespace() string {
	return e.Namespace
}

func (e *StructEvent) GetNewPath() string {
	switch e.EventType {
	case HardlinkEventType, SymlinkEventType:
		return e.NewPath
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
		return e.OldPath
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

func (e *StructEvent) GetPath() string {
	switch e.EventType {
	case OpenEventType:
		return e.Path
	default:
		logger.L().Warning("GetPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *StructEvent) GetPcomm() string {
	return e.Pcomm
}

func (e *StructEvent) GetPID() uint32 {
	return e.Pid
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
	return e.Ppid
}

func (e *StructEvent) GetProto() string {
	switch e.EventType {
	case NetworkEventType:
		return e.Proto
	default:
		logger.L().Warning("GetProto not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
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
	case SSHEventType:
		return e.SrcIP
	}
	return ""
}

func (e *StructEvent) GetSrcPort() uint16 {
	switch e.EventType {
	case SSHEventType:
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
	default:
		logger.L().Warning("GetSyscall not implemented for event type", helpers.String("eventType", string(e.EventType)))
		panic("GetSyscall not implemented for this event type")
	}
}

func (e *StructEvent) GetSyscalls() []string {
	switch e.EventType {
	case SyscallEventType:
		return []string{e.Syscall}
	default:
		logger.L().Warning("GetSyscalls not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
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
		logger.L().Warning("GetEventType not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *StructEvent) GetUid() *uint32 {
	switch e.EventType {
	case CapabilitiesEventType, ExecveEventType, ExitEventType, ForkEventType, HTTPEventType:
		return &e.Uid
	case OpenEventType:
		return &e.Uid
	default:
		logger.L().Warning("GetUid not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *StructEvent) GetUpperLayer() bool {
	switch e.EventType {
	case ExecveEventType:
		return e.UpperLayer
	default:
		logger.L().Warning("GetUpperLayer not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
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

func (e *StructEvent) SetExtra(extra interface{}) {
	e.Extra = extra
}

func (e *StructEvent) SetRequest(request *http.Request) {
	e.Request = request
}

func (e *StructEvent) SetResponse(response *http.Response) {
	e.Response = response
}
