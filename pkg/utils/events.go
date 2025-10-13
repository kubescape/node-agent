package utils

import (
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

type HTTPDataType int

const (
	Request  HTTPDataType = 2
	Response HTTPDataType = 3
)

type K8sEvent interface {
	GetNamespace() string
	GetPod() string
	GetTimestamp() types.Time
}

type EnrichEvent interface {
	K8sEvent
	GetComm() string
	GetContainer() string
	GetContainerID() string
	GetContainerImage() string
	GetContainerImageDigest() string
	GetError() int64
	GetEventType() EventType
	GetExtra() interface{}
	GetGid() *uint32
	GetHostNetwork() bool
	GetPcomm() string
	GetPID() uint32
	GetPodLabels() map[string]string
	GetPpid() uint32
	GetUid() *uint32
	SetExtra(extra interface{})
}

type CapabilitiesEvent interface {
	EnrichEvent
	GetCapability() string
	GetSyscall() string
}

type DNSEvent interface {
	EnrichEvent
	GetAddresses() []string
	GetDNSName() string
	GetNumAnswers() int
	GetQr() DNSPktType
}

type ExecEvent interface {
	EnrichEvent
	GetArgs() []string
	GetCwd() string
	GetExePath() string
	GetPupperLayer() bool
	GetUpperLayer() bool
}

type HttpEvent interface {
	HttpRawEvent
	GetDirection() consts.NetworkDirection
	GetInternal() bool
	GetRequest() *http.Request
	SetRequest(request *http.Request)
	SetResponse(response *http.Response)
	GetResponse() *http.Response
}

type HttpRawEvent interface {
	EnrichEvent
	GetBuf() []byte
	GetSocketInode() uint64
	GetSockFd() uint32
	GetSyscall() string
	GetType() HTTPDataType
}

type IOUring interface {
	EnrichEvent
	GetOpcode() int
}

type LinkEvent interface {
	EnrichEvent
	GetNewPath() string
	GetOldPath() string
}

type NetworkEvent interface {
	EnrichEvent
	GetDstEndpoint() types.L4Endpoint
	GetDstPort() uint16
	GetPktType() string
	GetPodHostIP() string
	GetPort() uint16
	GetProto() string
}

type OpenEvent interface {
	EnrichEvent
	GetFlags() []string
	GetFlagsRaw() uint32
	GetPath() string
	IsDir() bool
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
	GetSyscalls() []string
}

type EverythingEvent interface {
	CapabilitiesEvent
	DNSEvent
	ExecEvent
	HttpRawEvent // not HttpEvent as we need to parse the HTTP data first
	IOUring
	LinkEvent
	NetworkEvent
	OpenEvent
	SshEvent
	SyscallEvent
}

type EventType string

const (
	AllEventType          EventType = "all"
	CapabilitiesEventType EventType = "capabilities"
	DnsEventType          EventType = "dns"
	ExecveEventType       EventType = "exec"
	ExitEventType         EventType = "exit"
	ForkEventType         EventType = "fork"
	HTTPEventType         EventType = "http"
	HardlinkEventType     EventType = "hardlink"
	IoUringEventType      EventType = "iouring"
	NetworkEventType      EventType = "network"
	OpenEventType         EventType = "open"
	ProcfsEventType       EventType = "procfs"
	PtraceEventType       EventType = "ptrace"
	RandomXEventType      EventType = "randomx"
	SSHEventType          EventType = "ssh"
	SymlinkEventType      EventType = "symlink"
	SyscallEventType      EventType = "syscall"
)

// Get the path of the file on the node.
func GetHostFilePathFromEvent(event EnrichEvent, containerPid uint32) (string, error) {
	switch v := event.(type) {
	case ExecEvent:
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, GetExecPathFromEvent(v)))
		return realPath, nil
	case OpenEvent:
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, v.GetPath()))
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

func GetCommFromEvent(event any) string {
	if event == nil {
		return ""
	}

	v := reflect.ValueOf(event)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// Only proceed if it's a struct
	if v.Kind() != reflect.Struct {
		return ""
	}

	if commField := v.FieldByName("Comm"); commField.IsValid() && commField.Kind() == reflect.String {
		return commField.String()
	}

	return ""
}

// GetContainerIDFromEvent uses reflection to extract the ContainerID from any event type
// without requiring type conversion. Returns empty string if ContainerID field is not found.
func GetContainerIDFromEvent(event interface{}) string {
	if event == nil {
		return ""
	}

	v := reflect.ValueOf(event)
	// Handle pointer types
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// Only proceed if it's a struct
	if v.Kind() != reflect.Struct {
		return ""
	}

	// Try to get the Runtime field first
	if runtimeField := v.FieldByName("Runtime"); runtimeField.IsValid() {
		runtimeValue := runtimeField
		if runtimeValue.Kind() == reflect.Ptr {
			runtimeValue = runtimeValue.Elem()
		}

		// Only proceed if Runtime is a struct
		if runtimeValue.Kind() == reflect.Struct {
			// Try to get the ContainerID field from Runtime
			if containerIDField := runtimeValue.FieldByName("ContainerID"); containerIDField.IsValid() && containerIDField.Kind() == reflect.String {
				return containerIDField.String()
			}
		}
	}

	return ""
}
