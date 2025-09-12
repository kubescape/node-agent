package utils

import (
	"fmt"
	"reflect"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type K8sEvent interface {
	GetPod() string
	GetNamespace() string
	GetTimestamp() types.Time
}

type EnrichEvent interface {
	GetBaseEvent() *types.Event
	GetPID() uint64
	SetExtra(extra interface{})
	GetExtra() interface{}
	GetPod() string
	GetNamespace() string
	GetTimestamp() types.Time
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
func GetHostFilePathFromEvent(event K8sEvent, containerPid uint32) (string, error) {
	//if execEvent, ok := event.(*tracerexectype.Event); ok {
	//	realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, GetExecPathFromEvent(execEvent)))
	//	return realPath, nil
	//}

	//if openEvent, ok := event.(*traceropentype.Event); ok {
	//	realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, openEvent.FullPath))
	//	return realPath, nil
	//}
	return "", fmt.Errorf("event is not of type tracerexectype.Event or traceropentype.Event")
}

// Get the path of the executable from the given event.
func GetExecPathFromEvent(event *datasource.Data) string {
	//if len(event.Args) > 0 {
	//	if event.Args[0] != "" {
	//		return event.Args[0]
	//	}
	//}
	//return event.Comm
	return ""
}

// Get exec args from the given event.
func GetExecArgsFromEvent(event *datasource.Data) []string {
	//if len(event.Args) > 1 {
	//	return event.Args[1:]
	//}
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
