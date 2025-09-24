package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type DNSPktType string

const (
	DNSPktTypeQuery    DNSPktType = "Q"
	DNSPktTypeResponse DNSPktType = "R"
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

func (e *EnrichEvent) GetArgs() []string {
	switch e.EventType {
	case ExecveEventType:
		args, _ := e.Datasource.GetField("args").String(e.Data)
		return strings.Split(args, " ")
	default:
		return nil
	}
}

func (e *EnrichEvent) GetCapability() string {
	switch e.EventType {
	case CapabilitiesEventType:
		capability, _ := e.Datasource.GetField("cap").String(e.Data)
		return capability
	default:
		return ""
	}
}

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

func (e *EnrichEvent) GetCwd() string {
	switch e.EventType {
	case ExecveEventType:
		cwd, _ := e.Datasource.GetField("cwd").String(e.Data)
		return cwd
	default:
		return ""
	}
}

func (e *EnrichEvent) GetDstPort() uint16 {
	port, _ := e.Datasource.GetField("dst.port").Uint16(e.Data)
	return port
}

func (e *EnrichEvent) GetError() int64 {
	err, _ := e.Datasource.GetField("error_raw").Int64(e.Data)
	return err
}

func (e *EnrichEvent) GetExePath() string {
	switch e.EventType {
	case ExecveEventType:
		exepath, _ := e.Datasource.GetField("exepath").String(e.Data)
		return exepath
	default:
		return ""
	}
}

func (e *EnrichEvent) GetFlags() []string {
	switch e.EventType {
	case OpenEventType:
		flags, _ := e.Datasource.GetField("flags_raw").Int32(e.Data)
		return decodeFlags(flags)
	default:
		return nil
	}
}

func (e *EnrichEvent) GetGid() *uint32 {
	switch e.EventType {
	case ExecveEventType:
		gid, _ := e.Datasource.GetField("proc.creds.gid").Uint32(e.Data)
		return &gid
	case OpenEventType:
		gid, _ := e.Datasource.GetField("proc.gid").Uint32(e.Data)
		return &gid
	default:
		logger.L().Warning("GetGid not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *EnrichEvent) GetHostNetwork() bool {
	hostnetwork, _ := e.Datasource.GetField("k8s.hostNetwork").Bool(e.Data)
	return hostnetwork
}

func (e *EnrichEvent) IsDir() bool {
	raw, _ := e.Datasource.GetField("mode_raw").Uint32(e.Data)
	fileMode := os.FileMode(raw)
	return (fileMode & os.ModeType) == os.ModeDir // FIXME not sure if this is correct
}

func (e *EnrichEvent) GetNamespace() string {
	namespace, _ := e.Datasource.GetField("k8s.namespace").String(e.Data)
	return namespace
}

func (e *EnrichEvent) GetPath() string {
	path, _ := e.Datasource.GetField("fname").String(e.Data)
	return path
}

func (e *EnrichEvent) GetPcomm() string {
	pcomm, _ := e.Datasource.GetField("proc.parent.comm").String(e.Data)
	return pcomm
}

func (e *EnrichEvent) GetPid() uint32 {
	pid, _ := e.Datasource.GetField("proc.pid").Uint32(e.Data)
	return pid
}

func (e *EnrichEvent) GetPktType() string {
	pktType, _ := e.Datasource.GetField("type").String(e.Data)
	return pktType
}

func (e *EnrichEvent) GetPod() string {
	podName, _ := e.Datasource.GetField("k8s.podName").String(e.Data)
	return podName
}

func (e *EnrichEvent) GetPodLabels() map[string]string {
	podLabels, _ := e.Datasource.GetField("k8s.podLabels").String(e.Data)
	return parseStringToMap(podLabels)
}

func (e *EnrichEvent) GetPort() uint16 {
	port, _ := e.Datasource.GetField("src.port").Uint16(e.Data)
	return port
}

func (e *EnrichEvent) GetPpid() uint32 {
	ppid, _ := e.Datasource.GetField("proc.parent.pid").Uint32(e.Data)
	return ppid
}

func (e *EnrichEvent) GetPupperLayer() bool {
	switch e.EventType {
	case ExecveEventType:
		pupperLayer, _ := e.Datasource.GetField("pupper_layer").Bool(e.Data)
		return pupperLayer
	default:
		return false
	}
}

func (e *EnrichEvent) GetSyscall() string {
	switch e.EventType {
	case CapabilitiesEventType:
		syscallRaw, _ := e.Datasource.GetField("syscall_raw").Uint16(e.Data)
		return syscalls.SyscallGetName(syscallRaw)
	default:
		return ""
	}
}

func (e *EnrichEvent) GetSyscalls() []string {
	switch e.EventType {
	case SyscallEventType:
		syscallsBuffer, _ := e.Datasource.GetField("syscalls").Bytes(e.Data)
		return decodeSyscalls(syscallsBuffer)
	default:
		return nil
	}
}

func (e *EnrichEvent) GetTimestamp() types.Time {
	switch e.EventType {
	case NetworkEventType, SyscallEventType:
		return types.Time(time.Now().UnixNano())
	default:
		timeStampRaw, _ := e.Datasource.GetField("timestamp_raw").Uint64(e.Data)
		timeStamp := gadgets.WallTimeFromBootTime(timeStampRaw)
		return timeStamp
	}
}

func (e *EnrichEvent) GetUid() *uint32 {
	switch e.EventType {
	case ExecveEventType:
		uid, _ := e.Datasource.GetField("proc.creds.uid").Uint32(e.Data)
		return &uid
	case OpenEventType:
		uid, _ := e.Datasource.GetField("proc.uid").Uint32(e.Data)
		return &uid
	default:
		logger.L().Warning("GetUid not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *EnrichEvent) GetUpperLayer() bool {
	switch e.EventType {
	case ExecveEventType:
		upperLayer, _ := e.Datasource.GetField("upper_layer").Bool(e.Data)
		return upperLayer
	default:
		return false
	}
}

func (e *EnrichEvent) GetQr() DNSPktType {
	// TODO: implement for DNS events
	return ""
}

func (e *EnrichEvent) GetNumAnswers() int {
	// TODO: implement for DNS events
	return 0
}

func (e *EnrichEvent) GetAddresses() []string {
	// TODO: implement for DNS events
	return nil
}

func (e *EnrichEvent) GetDNSName() string {
	// TODO: implement for DNS events
	return ""
}

func (e *EnrichEvent) GetProto() string {
	// TODO fix proto raw to string mapping
	proto, _ := e.Datasource.GetField("dst.proto_raw").String(e.Data)
	return proto
}

func (e *EnrichEvent) GetDstEndpoint() types.L4Endpoint {
	// TODO: implement for network events
	return types.L4Endpoint{
		L3Endpoint: types.L3Endpoint{
			Addr:      "",
			Version:   0,
			Namespace: "",
			Name:      "",
			Kind:      "",
			PodLabels: nil,
		},
	}
}

func (e *EnrichEvent) GetPodHostIP() string {
	// TODO: implement for network events
	return ""
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
func GetHostFilePathFromEvent(event *EnrichEvent, containerPid uint32) (string, error) {
	switch event.EventType {
	case ExecveEventType:
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, GetExecPathFromEvent(event)))
		return realPath, nil
	case OpenEventType:
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, event.GetPath()))
		return realPath, nil
	default:
		return "", fmt.Errorf("event is not of type tracerexectype.Event or traceropentype.Event")
	}
}

// Get the path of the executable from the given event.
func GetExecPathFromEvent(event *EnrichEvent) string {
	if args := event.GetArgs(); len(args) > 0 {
		if args[0] != "" {
			return args[0]
		}
	}
	return event.GetComm()
}

// Get exec args from the given event.
func GetExecArgsFromEvent(event *EnrichEvent) []string {
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
