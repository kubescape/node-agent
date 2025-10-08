package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/picatz/xcel"
)

type DNSPktType string

const (
	DNSPktTypeQuery    DNSPktType = "Q"
	DNSPktTypeResponse DNSPktType = "R"
)

type DatasourceEvent struct {
	Data       datasource.Data
	Datasource datasource.DataSource
	EventType  EventType
	extra      interface{}
}

var _ EnrichEvent = (*DatasourceEvent)(nil)
var _ DNSEvent = (*DatasourceEvent)(nil)
var _ ContainerEvent = (*DatasourceEvent)(nil)

var DatasourceFields = map[string]*celtypes.FieldType{
	"args": {
		Type: celtypes.ListType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil || x.Raw.EventType != ExecveEventType {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetArgs(), nil
		}),
	},
	"capName": {
		Type: celtypes.StringType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil || x.Raw.EventType != CapabilitiesEventType {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetCapability(), nil
		}),
	},
	"comm": {
		Type: celtypes.StringType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetComm(), nil
		}),
	},
	"dst.addr": {
		Type: celtypes.StringType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil || x.Raw.EventType != NetworkEventType {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetDstEndpoint().Addr, nil
		}),
	},
	"exepath": {
		Type: celtypes.StringType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil || x.Raw.EventType != ExecveEventType {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetExePath(), nil
		}),
	},
	"fullPath": {
		Type: celtypes.StringType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil || x.Raw.EventType != ExecveEventType {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetExecFullPathFromEvent(), nil
		}),
	},
	"k8s.containerName": {
		Type: celtypes.StringType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetContainer(), nil
		}),
	},
	"name": {
		Type: celtypes.StringType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil || x.Raw.EventType != DnsEventType {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetDNSName(), nil
		}),
	},
	"pcomm": {
		Type: celtypes.StringType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetPcomm(), nil
		}),
	},
	"pid": {
		Type: celtypes.UintType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetPID(), nil
		}),
	},
	"ppid": {
		Type: celtypes.UintType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetPpid(), nil
		}),
	},
	"port": {
		Type: celtypes.UintType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil || x.Raw.EventType != NetworkEventType {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetPort(), nil
		}),
	},
	"proto": {
		Type: celtypes.StringType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil || x.Raw.EventType != NetworkEventType {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetProto(), nil
		}),
	},
	"runtime.containerId": {
		Type: celtypes.StringType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetContainerID(), nil
		}),
	},
	"syscallName": {
		Type: celtypes.StringType,
		IsSet: ref.FieldTester(func(target any) bool {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil || x.Raw.EventType != CapabilitiesEventType {
				return false
			}
			return true
		}),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[*DatasourceEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetSyscall(), nil
		}),
	},
}

func (e *DatasourceEvent) GetAddresses() []string {
	// TODO: implement for DNS events
	return nil
}

func (e *DatasourceEvent) GetArgs() []string {
	switch e.EventType {
	case ExecveEventType:
		args, _ := e.Datasource.GetField("args").String(e.Data)
		return strings.Split(args, " ")
	default:
		return nil
	}
}

func (e *DatasourceEvent) GetCapability() string {
	switch e.EventType {
	case CapabilitiesEventType:
		capability, _ := e.Datasource.GetField("cap").String(e.Data)
		return capability
	default:
		return ""
	}
}

func (e *DatasourceEvent) GetComm() string {
	comm, _ := e.Datasource.GetField("proc.comm").String(e.Data)
	return comm
}

func (e *DatasourceEvent) GetContainer() string {
	containerName, _ := e.Datasource.GetField("k8s.containerName").String(e.Data)
	return containerName
}

func (e *DatasourceEvent) GetContainerID() string {
	containerId, _ := e.Datasource.GetField("runtime.containerId").String(e.Data)
	return containerId
}

func (e *DatasourceEvent) GetContainerImage() string {
	containerImageName, _ := e.Datasource.GetField("runtime.containerImageName").String(e.Data)
	return containerImageName
}

func (e *DatasourceEvent) GetContainerImageDigest() string {
	containerImageDigest, _ := e.Datasource.GetField("runtime.containerImageDigest").String(e.Data)
	return containerImageDigest
}

func (e *DatasourceEvent) GetCwd() string {
	switch e.EventType {
	case ExecveEventType:
		cwd, _ := e.Datasource.GetField("cwd").String(e.Data)
		return cwd
	default:
		return ""
	}
}

func (e *DatasourceEvent) GetDNSName() string {
	// TODO: implement for DNS events
	return ""
}

func (e *DatasourceEvent) GetDstEndpoint() types.L4Endpoint {
	switch e.EventType {
	case NetworkEventType:
		addr, _ := e.Datasource.GetField("dst.addr_raw.v4").Uint32(e.Data)
		kind, _ := e.Datasource.GetField("dst.k8s.kind").String(e.Data)
		name, _ := e.Datasource.GetField("dst.k8s.name").String(e.Data)
		namespace, _ := e.Datasource.GetField("dst.k8s.namespace").String(e.Data)
		podLabels, _ := e.Datasource.GetField("dst.k8s.labels").String(e.Data)
		version, _ := e.Datasource.GetField("dst.version").Uint8(e.Data)
		port, _ := e.Datasource.GetField("dst.port").Uint16(e.Data)
		proto, _ := e.Datasource.GetField("dst.proto_raw").Uint16(e.Data)
		return types.L4Endpoint{
			L3Endpoint: types.L3Endpoint{
				Addr:      rawIPv4ToString(addr),
				Version:   version,
				Namespace: namespace,
				Name:      name,
				Kind:      types.EndpointKind(kind),
				PodLabels: parseStringToMap(podLabels),
			},
			Port:  port,
			Proto: proto,
		}
	default:
		return types.L4Endpoint{}
	}
}

func (e *DatasourceEvent) GetDstPort() uint16 {
	switch e.EventType {
	case NetworkEventType:
		port, _ := e.Datasource.GetField("dst.port").Uint16(e.Data)
		return port
	default:
		return 0
	}
}

func (e *DatasourceEvent) GetError() int64 {
	err, _ := e.Datasource.GetField("error_raw").Int64(e.Data)
	return err
}

// Get exec args from the given event.
func (e *DatasourceEvent) GetExecArgsFromEvent() []string {
	if args := e.GetArgs(); len(args) > 1 {
		return args[1:]
	}
	return []string{}
}

func (e *DatasourceEvent) GetExecFullPathFromEvent() string {
	if path := e.GetExePath(); path != "" {
		return path
	}
	return e.GetExecPathFromEvent()
}

func (e *DatasourceEvent) GetExePath() string {
	switch e.EventType {
	case ExecveEventType:
		exepath, _ := e.Datasource.GetField("exepath").String(e.Data)
		return exepath
	default:
		return ""
	}
}

// Get the path of the executable from the given event.
func (e *DatasourceEvent) GetExecPathFromEvent() string {
	if args := e.GetArgs(); len(args) > 0 {
		if args[0] != "" {
			return args[0]
		}
	}
	return e.GetComm()
}

func (e *DatasourceEvent) GetExtra() interface{} {
	return e.extra
}

func (e *DatasourceEvent) GetFlags() []string {
	switch e.EventType {
	case OpenEventType:
		flags, _ := e.Datasource.GetField("flags_raw").Int32(e.Data)
		return decodeFlags(flags)
	default:
		return nil
	}
}

func (e *DatasourceEvent) GetGid() *uint32 {
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

// Get the path of the file on the node.
func (e *DatasourceEvent) GetHostFilePathFromEvent(containerPid uint32) (string, error) {
	switch e.EventType {
	case ExecveEventType:
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, e.GetExecPathFromEvent()))
		return realPath, nil
	case OpenEventType:
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, e.GetPath()))
		return realPath, nil
	default:
		return "", fmt.Errorf("event is not of type tracerexectype.Event or traceropentype.Event")
	}
}

func (e *DatasourceEvent) GetHostNetwork() bool {
	hostNetwork, _ := e.Datasource.GetField("k8s.hostnetwork").Bool(e.Data)
	return hostNetwork
}

func (e *DatasourceEvent) GetNamespace() string {
	namespace, _ := e.Datasource.GetField("k8s.namespace").String(e.Data)
	return namespace
}

func (e *DatasourceEvent) GetNumAnswers() int {
	// TODO: implement for DNS events
	return 0
}

func (e *DatasourceEvent) GetPath() string {
	path, _ := e.Datasource.GetField("fname").String(e.Data)
	return path
}

func (e *DatasourceEvent) GetPcomm() string {
	pcomm, _ := e.Datasource.GetField("proc.parent.comm").String(e.Data)
	return pcomm
}

func (e *DatasourceEvent) GetPID() uint32 {
	pid, _ := e.Datasource.GetField("proc.pid").Uint32(e.Data)
	return pid
}

func (e *DatasourceEvent) GetPktType() string {
	//pktType, _ := e.Datasource.GetField("type").String(e.Data)
	return "OUTGOING" // FIXME: this is not present in the trace_tcp event
}

func (e *DatasourceEvent) GetPod() string {
	podName, _ := e.Datasource.GetField("k8s.podName").String(e.Data)
	return podName
}

func (e *DatasourceEvent) GetPodHostIP() string {
	switch e.EventType {
	case NetworkEventType:
		hostIP, _ := e.Datasource.GetField("k8s.hostIP").String(e.Data)
		return hostIP
	default:
		return ""
	}
}

func (e *DatasourceEvent) GetPodLabels() map[string]string {
	podLabels, _ := e.Datasource.GetField("k8s.podLabels").String(e.Data)
	return parseStringToMap(podLabels)
}

func (e *DatasourceEvent) GetPort() uint16 {
	switch e.EventType {
	case NetworkEventType:
		port, _ := e.Datasource.GetField("src.port").Uint16(e.Data)
		return port
	default:
		return 0
	}
}

func (e *DatasourceEvent) GetPpid() uint32 {
	ppid, _ := e.Datasource.GetField("proc.parent.pid").Uint32(e.Data)
	return ppid
}

func (e *DatasourceEvent) GetProto() string {
	switch e.EventType {
	case NetworkEventType:
		// TODO fix proto raw to string mapping
		proto, _ := e.Datasource.GetField("dst.proto_raw").String(e.Data)
		return proto
	default:
		return ""
	}
}

func (e *DatasourceEvent) GetPupperLayer() bool {
	switch e.EventType {
	case ExecveEventType:
		pupperLayer, _ := e.Datasource.GetField("pupper_layer").Bool(e.Data)
		return pupperLayer
	default:
		return false
	}
}

func (e *DatasourceEvent) GetQr() DNSPktType {
	// TODO: implement for DNS events
	return ""
}

func (e *DatasourceEvent) GetSyscall() string {
	switch e.EventType {
	case CapabilitiesEventType:
		syscallRaw, _ := e.Datasource.GetField("syscall_raw").Uint16(e.Data)
		return syscalls.SyscallGetName(syscallRaw)
	default:
		return ""
	}
}

func (e *DatasourceEvent) GetSyscalls() []string {
	switch e.EventType {
	case SyscallEventType:
		syscallsBuffer, _ := e.Datasource.GetField("syscalls").Bytes(e.Data)
		return decodeSyscalls(syscallsBuffer)
	default:
		return nil
	}
}

func (e *DatasourceEvent) GetTimestamp() types.Time {
	switch e.EventType {
	case SyscallEventType:
		return types.Time(time.Now().UnixNano())
	default:
		timeStampRaw, _ := e.Datasource.GetField("timestamp_raw").Uint64(e.Data)
		timeStamp := gadgets.WallTimeFromBootTime(timeStampRaw)
		return timeStamp
	}
}

func (e *DatasourceEvent) GetUid() *uint32 {
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

func (e *DatasourceEvent) GetUpperLayer() bool {
	switch e.EventType {
	case ExecveEventType:
		upperLayer, _ := e.Datasource.GetField("upper_layer").Bool(e.Data)
		return upperLayer
	default:
		return false
	}
}

func (e *DatasourceEvent) IsDir() bool {
	raw, _ := e.Datasource.GetField("mode_raw").Uint32(e.Data)
	fileMode := os.FileMode(raw)
	return (fileMode & os.ModeType) == os.ModeDir // FIXME not sure if this is correct
}

func (e *DatasourceEvent) SetExtra(extra interface{}) {
	e.extra = extra
}
