package utils

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

type HTTPDataType int

const (
	HostPktType                  = "HOST"
	OutgoingPktType              = "OUTGOING"
	Request         HTTPDataType = 2
	Response        HTTPDataType = 3
)

type K8sEvent interface {
	GetContainerID() string
	GetEventType() EventType
	GetNamespace() string
	GetPod() string
	GetTimestamp() types.Time
	HasDroppedEvents() bool
	Release()
}

type EnrichEvent interface {
	K8sEvent
	GetComm() string
	GetContainer() string
	GetContainerImage() string
	GetContainerImageDigest() string
	GetError() int64
	GetExtra() interface{}
	GetGid() *uint32
	GetHostNetwork() bool
	GetMountNsID() uint64
	GetPcomm() string
	GetPID() uint32
	GetPID64() uint64
	GetPodLabels() map[string]string
	GetPpid() uint32
	GetUid() *uint32
	SetExtra(extra interface{})
}

type BpfEvent interface {
	EnrichEvent
	GetExePath() string
	GetCmd() uint32
	GetAttrSize() uint32
	GetUpperLayer() bool
}

type CapabilitiesEvent interface {
	EnrichEvent
	GetCapability() string
	GetSyscall() string
}

type DNSEvent interface {
	EnrichEvent
	GetAddresses() []string
	GetCwd() string
	GetDNSName() string
	GetDstIP() string
	GetDstPort() uint16
	GetExePath() string
	GetNumAnswers() int
	GetProto() string
	GetQr() DNSPktType
	GetSrcIP() string
	GetSrcPort() uint16
}

type ExecEvent interface {
	EnrichEvent
	GetArgs() []string
	GetCwd() string
	GetExePath() string
	GetPupperLayer() bool
	GetUpperLayer() bool
}

type ExitEvent interface {
	EnrichEvent
	GetExitCode() uint32
	GetSignal() uint32
}

type ForkEvent interface {
	EnrichEvent
	GetExePath() string
}

type HttpEvent interface {
	HttpRawEvent
	GetDirection() consts.NetworkDirection
	GetInternal() bool
	GetOtherIp() string
	GetRequest() *http.Request
	GetResponse() *http.Response
	SetResponse(response *http.Response)
}

type HttpRawEvent interface {
	EnrichEvent
	GetBuf() []byte
	GetDstIP() string
	GetDstPort() uint16
	GetSockFd() uint32
	GetSocketInode() uint64
	GetSrcIP() string
	GetSrcPort() uint16
	GetSyscall() string
	GetType() HTTPDataType
	MakeHttpEvent(request *http.Request, direction consts.NetworkDirection, ip net.IP) HttpEvent
}

type IOUring interface {
	EnrichEvent
	GetFlags() []string
	GetIdentifier() string
	GetOpcode() int
}

type KmodEvent interface {
	EnrichEvent
	GetModule() string
	GetExePath() string
	GetSyscall() string
	GetUpperLayer() bool
}

type LinkEvent interface {
	EnrichEvent
	GetExePath() string
	GetNewPath() string
	GetOldPath() string
	GetUpperLayer() bool
}

type NetworkEvent interface {
	EnrichEvent
	GetDstEndpoint() types.L4Endpoint
	GetDstPort() uint16
	GetPktType() string
	GetPodHostIP() string
	GetProto() string
}

type OpenEvent interface {
	EnrichEvent
	GetFlags() []string
	GetFlagsRaw() uint32
	GetFullPath() string
	GetPath() string
	IsDir() bool
}

type PtraceEvent interface {
	EnrichEvent
	GetExePath() string
}

type SshEvent interface {
	EnrichEvent
	GetDstIP() string
	GetDstPort() uint16
	GetSrcIP() string
	GetSrcPort() uint16
}

type SyscallEvent interface {
	EnrichEvent
	GetSyscall() string
}

type UnshareEvent interface {
	EnrichEvent
	GetExePath() string
	// GetFlags() uint64
	GetUpperLayer() bool
}

type EventType string

const (
	AllEventType          EventType = "all"
	BpfEventType          EventType = "bpf"
	CapabilitiesEventType EventType = "capabilities"
	DnsEventType          EventType = "dns"
	ExecveEventType       EventType = "exec"
	ExitEventType         EventType = "exit"
	ForkEventType         EventType = "fork"
	HTTPEventType         EventType = "http"
	HardlinkEventType     EventType = "hardlink"
	IoUringEventType      EventType = "iouring"
	KmodEventType         EventType = "kmod"
	NetworkEventType      EventType = "network"
	OpenEventType         EventType = "open"
	ProcfsEventType       EventType = "procfs"
	PtraceEventType       EventType = "ptrace"
	RandomXEventType      EventType = "randomx"
	SSHEventType          EventType = "ssh"
	SymlinkEventType      EventType = "symlink"
	SyscallEventType      EventType = "syscall"
	UnshareEventType      EventType = "unshare"
)

// Get the path of the file on the node.
func GetHostFilePathFromEvent(event EnrichEvent, containerPid uint32) (string, error) {
	switch event.GetEventType() {
	case ExecveEventType:
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, GetExecPathFromEvent(event.(ExecEvent))))
		return realPath, nil
	case OpenEventType:
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, event.(OpenEvent).GetFullPath()))
		return realPath, nil
	default:
		return "", fmt.Errorf("event is not of type exec or open")
	}
}

// Get the path of the executable from the given event.
func GetExecPathFromEvent(event ExecEvent) string {
	if args := event.GetArgs(); len(args) > 0 {
		if args[0] != "" {
			return args[0]
		}
	}
	return event.GetComm()
}

// Get exec args from the given event.
func GetExecArgsFromEvent(event ExecEvent) []string {
	if args := event.GetArgs(); len(args) > 1 {
		return args[1:]
	}
	return []string{}
}

// protoNumToString converts a protocol number to its string representation
func protoNumToString(protoNum uint16) string {
	switch protoNum {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return ""
	}
}
