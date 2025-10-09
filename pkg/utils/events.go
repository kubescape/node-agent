package utils

import (
	"reflect"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
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
	GetExecArgsFromEvent() []string
	GetExecFullPathFromEvent() string
	GetExePath() string
	GetExecPathFromEvent() string
	GetGid() *uint32
	GetHostFilePathFromEvent(containerPid uint32) (string, error)
	GetPupperLayer() bool
	GetUpperLayer() bool
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
	GetGid() *uint32
	GetHostFilePathFromEvent(containerPid uint32) (string, error)
	GetPath() string
	IsDir() bool
}

type SyscallEvent interface {
	EnrichEvent
	GetSyscalls() []string
}

type EverythingEvent interface {
	CapabilitiesEvent
	DNSEvent
	ExecEvent
	NetworkEvent
	OpenEvent
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
