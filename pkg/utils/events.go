package utils

import (
	"fmt"
	"reflect"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type K8sEvent interface {
	GetContainer() string
	GetContainerID() string
	GetContainerImage() string
	GetContainerImageDigest() string
	GetHostNetwork() bool
	GetNamespace() string
	GetPod() string
	GetTimestamp() types.Time
}

type EnrichEvent struct {
	Data       datasource.Data
	Datasource datasource.DataSource
	EventType  EventType
	extra      interface{}
}

var _ K8sEvent = (*EnrichEvent)(nil)

func (e *EnrichEvent) GetExtra() interface{} {
	return e.extra
}

// TODO maybe cache FieldAccessors?

func (e *EnrichEvent) GetComm() string {
	comm, _ := e.Datasource.GetField("proc.comm").String(e.Data)
	return comm
}

func (e *EnrichEvent) GetContainer() string {
	containerName, _ := e.Datasource.GetField("k8s.containerName").String(e.Data)
	return containerName
}

func (e *EnrichEvent) GetContainerID() string {
	containerId, _ := e.Datasource.GetField("runtime.containerId").String(e.Data)
	return containerId
}

func (e *EnrichEvent) GetContainerImage() string {
	containerImageName, _ := e.Datasource.GetField("runtime.containerImageName").String(e.Data)
	return containerImageName
}

func (e *EnrichEvent) GetContainerImageDigest() string {
	containerImageDigest, _ := e.Datasource.GetField("runtime.containerImageDigest").String(e.Data)
	return containerImageDigest
}

func (e *EnrichEvent) GetError() int64 {
	err, _ := e.Datasource.GetField("error_raw").Int64(e.Data)
	return err
}

// GetFlags decodes the open flags from the event, returns nil if not an open event
func (e *EnrichEvent) GetFlags() []string {
	if e.EventType != OpenEventType {
		return nil
	}
	flags, _ := e.Datasource.GetField("flags_raw").Int32(e.Data)
	return decodeFlags(flags)
}

func (e *EnrichEvent) GetGid() *uint32 {
	gid, _ := e.Datasource.GetField("proc.gid").Uint32(e.Data)
	return &gid
}

func (e *EnrichEvent) GetHostNetwork() bool {
	hostnetwork, _ := e.Datasource.GetField("k8s.hostNetwork").Bool(e.Data)
	return hostnetwork
}

func (e *EnrichEvent) GetNamespace() string {
	namespace, _ := e.Datasource.GetField("k8s.namespace").String(e.Data)
	return namespace
}

func (e *EnrichEvent) GetPath() string {
	path, _ := e.Datasource.GetField("fname").String(e.Data)
	return path
}

func (e *EnrichEvent) GetPid() uint32 {
	pid, _ := e.Datasource.GetField("proc.pid").Uint32(e.Data)
	return pid
}

func (e *EnrichEvent) GetPod() string {
	podName, _ := e.Datasource.GetField("k8s.podName").String(e.Data)
	return podName
}

func (e *EnrichEvent) GetTimestamp() types.Time {
	timeStampRaw, _ := e.Datasource.GetField("timestamp_raw").Uint64(e.Data)
	timeStamp := gadgets.WallTimeFromBootTime(timeStampRaw)
	return timeStamp
}

func (e *EnrichEvent) GetUid() *uint32 {
	uid, _ := e.Datasource.GetField("proc.uid").Uint32(e.Data)
	return &uid
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
