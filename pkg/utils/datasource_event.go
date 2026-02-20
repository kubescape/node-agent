package utils

import (
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	igconsts "github.com/inspektor-gadget/inspektor-gadget/gadgets/trace_exec/consts"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

type DNSPktType string

const (
	DNSPktTypeQuery    DNSPktType = "Q"
	DNSPktTypeResponse DNSPktType = "R"
)

var (
	fieldCaches = sync.Map{}
)

type DatasourceEvent struct {
	Data            datasource.Data
	Datasource      datasource.DataSource
	Direction       consts.NetworkDirection
	EventType       EventType
	FullPathTracing bool
	Internal        bool
	Request         *http.Request
	Response        *http.Response
	Syscall         string
	extra           interface{}
}

var _ BpfEvent = (*DatasourceEvent)(nil)
var _ CapabilitiesEvent = (*DatasourceEvent)(nil)
var _ DNSEvent = (*DatasourceEvent)(nil)
var _ ExecEvent = (*DatasourceEvent)(nil)
var _ ExitEvent = (*DatasourceEvent)(nil)
var _ ForkEvent = (*DatasourceEvent)(nil)
var _ HttpEvent = (*DatasourceEvent)(nil)
var _ HttpRawEvent = (*DatasourceEvent)(nil)
var _ IOUring = (*DatasourceEvent)(nil)
var _ KubeletTLSEvent = (*DatasourceEvent)(nil)
var _ KmodEvent = (*DatasourceEvent)(nil)
var _ LinkEvent = (*DatasourceEvent)(nil)
var _ NetworkEvent = (*DatasourceEvent)(nil)
var _ OpenEvent = (*DatasourceEvent)(nil)
var _ SshEvent = (*DatasourceEvent)(nil)
var _ SyscallEvent = (*DatasourceEvent)(nil)
var _ UnshareEvent = (*DatasourceEvent)(nil)

var errFieldNotFound = errors.New("field not found")

type nullFieldAccessor struct{}

func (n *nullFieldAccessor) Name() string                                 { return "" }
func (n *nullFieldAccessor) FullName() string                             { return "" }
func (n *nullFieldAccessor) Size() uint32                                 { return 0 }
func (n *nullFieldAccessor) Get(data datasource.Data) []byte              { return nil }
func (n *nullFieldAccessor) Set(data datasource.Data, value []byte) error { return nil }
func (n *nullFieldAccessor) IsRequested() bool                            { return false }
func (n *nullFieldAccessor) AddSubField(name string, kind api.Kind, opts ...datasource.FieldOption) (datasource.FieldAccessor, error) {
	return nil, errFieldNotFound
}
func (n *nullFieldAccessor) GetSubFieldsWithTag(tag ...string) []datasource.FieldAccessor { return nil }
func (n *nullFieldAccessor) Parent() datasource.FieldAccessor                             { return nil }
func (n *nullFieldAccessor) SubFields() []datasource.FieldAccessor                        { return nil }
func (n *nullFieldAccessor) SetHidden(hidden bool, recurse bool)                          {}
func (n *nullFieldAccessor) Type() api.Kind                                               { return api.Kind_Invalid }
func (n *nullFieldAccessor) Flags() uint32                                                { return 0 }
func (n *nullFieldAccessor) Tags() []string                                               { return nil }
func (n *nullFieldAccessor) AddTags(tags ...string)                                       {}
func (n *nullFieldAccessor) HasAllTagsOf(tags ...string) bool                             { return false }
func (n *nullFieldAccessor) HasAnyTagsOf(tags ...string) bool                             { return false }
func (n *nullFieldAccessor) Annotations() map[string]string                               { return nil }
func (n *nullFieldAccessor) AddAnnotation(key, value string)                              {}
func (n *nullFieldAccessor) RemoveReference(recurse bool)                                 {}
func (n *nullFieldAccessor) Rename(string) error                                          { return errFieldNotFound }

func (n *nullFieldAccessor) Uint8(datasource.Data) (uint8, error)     { return 0, errFieldNotFound }
func (n *nullFieldAccessor) Uint16(datasource.Data) (uint16, error)   { return 0, errFieldNotFound }
func (n *nullFieldAccessor) Uint32(datasource.Data) (uint32, error)   { return 0, errFieldNotFound }
func (n *nullFieldAccessor) Uint64(datasource.Data) (uint64, error)   { return 0, errFieldNotFound }
func (n *nullFieldAccessor) Int8(datasource.Data) (int8, error)       { return 0, errFieldNotFound }
func (n *nullFieldAccessor) Int16(datasource.Data) (int16, error)     { return 0, errFieldNotFound }
func (n *nullFieldAccessor) Int32(datasource.Data) (int32, error)     { return 0, errFieldNotFound }
func (n *nullFieldAccessor) Int64(datasource.Data) (int64, error)     { return 0, errFieldNotFound }
func (n *nullFieldAccessor) Float32(datasource.Data) (float32, error) { return 0, errFieldNotFound }
func (n *nullFieldAccessor) Float64(datasource.Data) (float64, error) { return 0, errFieldNotFound }
func (n *nullFieldAccessor) String(datasource.Data) (string, error)   { return "", errFieldNotFound }
func (n *nullFieldAccessor) Bytes(datasource.Data) ([]byte, error)    { return nil, errFieldNotFound }
func (n *nullFieldAccessor) Bool(datasource.Data) (bool, error)       { return false, errFieldNotFound }

func (n *nullFieldAccessor) Uint8Array(datasource.Data) ([]uint8, error) {
	return nil, errFieldNotFound
}
func (n *nullFieldAccessor) Uint16Array(datasource.Data) ([]uint16, error) {
	return nil, errFieldNotFound
}
func (n *nullFieldAccessor) Uint32Array(datasource.Data) ([]uint32, error) {
	return nil, errFieldNotFound
}
func (n *nullFieldAccessor) Uint64Array(datasource.Data) ([]uint64, error) {
	return nil, errFieldNotFound
}
func (n *nullFieldAccessor) Int8Array(datasource.Data) ([]int8, error) { return nil, errFieldNotFound }
func (n *nullFieldAccessor) Int16Array(datasource.Data) ([]int16, error) {
	return nil, errFieldNotFound
}
func (n *nullFieldAccessor) Int32Array(datasource.Data) ([]int32, error) {
	return nil, errFieldNotFound
}
func (n *nullFieldAccessor) Int64Array(datasource.Data) ([]int64, error) {
	return nil, errFieldNotFound
}
func (n *nullFieldAccessor) Float32Array(datasource.Data) ([]float32, error) {
	return nil, errFieldNotFound
}
func (n *nullFieldAccessor) Float64Array(datasource.Data) ([]float64, error) {
	return nil, errFieldNotFound
}

func (n *nullFieldAccessor) PutUint8(datasource.Data, uint8) error     { return errFieldNotFound }
func (n *nullFieldAccessor) PutUint16(datasource.Data, uint16) error   { return errFieldNotFound }
func (n *nullFieldAccessor) PutUint32(datasource.Data, uint32) error   { return errFieldNotFound }
func (n *nullFieldAccessor) PutUint64(datasource.Data, uint64) error   { return errFieldNotFound }
func (n *nullFieldAccessor) PutInt8(datasource.Data, int8) error       { return errFieldNotFound }
func (n *nullFieldAccessor) PutInt16(datasource.Data, int16) error     { return errFieldNotFound }
func (n *nullFieldAccessor) PutInt32(datasource.Data, int32) error     { return errFieldNotFound }
func (n *nullFieldAccessor) PutInt64(datasource.Data, int64) error     { return errFieldNotFound }
func (n *nullFieldAccessor) PutFloat32(datasource.Data, float32) error { return errFieldNotFound }
func (n *nullFieldAccessor) PutFloat64(datasource.Data, float64) error { return errFieldNotFound }
func (n *nullFieldAccessor) PutString(datasource.Data, string) error   { return errFieldNotFound }
func (n *nullFieldAccessor) PutBytes(datasource.Data, []byte) error    { return errFieldNotFound }
func (n *nullFieldAccessor) PutBool(datasource.Data, bool) error       { return errFieldNotFound }

var missingFieldAccessor datasource.FieldAccessor = &nullFieldAccessor{}

func (e *DatasourceEvent) getFieldAccessor(fieldName string) datasource.FieldAccessor {
	if e == nil {
		return missingFieldAccessor
	}

	cacheVal, ok := fieldCaches.Load(e.EventType)
	if !ok {
		cacheVal, _ = fieldCaches.LoadOrStore(e.EventType, &sync.Map{})
	}

	m, ok := cacheVal.(*sync.Map)
	if !ok {
		return missingFieldAccessor
	}

	accessor, ok := m.Load(fieldName)
	if !ok {
		if e.Datasource == nil {
			return missingFieldAccessor
		}
		field := e.Datasource.GetField(fieldName)
		accessor, _ = m.LoadOrStore(fieldName, field)
	}

	// Handle case where field doesn't exist
	if accessor == nil {
		return missingFieldAccessor
	}

	res, ok := accessor.(datasource.FieldAccessor)
	if !ok {
		return missingFieldAccessor
	}

	return res
}

func (e *DatasourceEvent) GetAttrSize() uint32 {
	switch e.EventType {
	case BpfEventType:
		attrSize, _ := e.getFieldAccessor("attr_size").Uint32(e.Data)
		return attrSize
	default:
		logger.L().Warning("GetAttrSize not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetAddresses() []string {
	switch e.EventType {
	case DnsEventType:
		args, _ := e.getFieldAccessor("addresses").String(e.Data)
		return strings.Split(args, ",")
	default:
		logger.L().Warning("GetAddresses not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *DatasourceEvent) GetArgs() []string {
	switch e.EventType {
	case ExecveEventType:
		args, _ := e.getFieldAccessor("args").String(e.Data)
		return strings.Split(args, igconsts.ArgsSeparator)
	default:
		logger.L().Warning("GetArgs not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *DatasourceEvent) GetBuf() []byte {
	switch e.EventType {
	case HTTPEventType:
		buf, _ := e.getFieldAccessor("buf").Bytes(e.Data)
		return buf
	default:
		logger.L().Warning("GetBuf not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *DatasourceEvent) GetCapability() string {
	switch e.EventType {
	case CapabilitiesEventType:
		capability, _ := e.getFieldAccessor("cap").String(e.Data)
		return capability
	default:
		logger.L().Warning("GetCapability not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetCmd() uint32 {
	switch e.EventType {
	case BpfEventType:
		cmd, _ := e.getFieldAccessor("cmd").Uint32(e.Data)
		return cmd
	default:
		logger.L().Warning("GetCmd not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetComm() string {
	switch e.EventType {
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		container := e.GetContainer()
		return container
	case KubeletTLSEventType:
		commValue, _ := e.getFieldAccessor("comm").String(e.Data)
		return commValue
	default:
		commValue, _ := e.getFieldAccessor("proc.comm").String(e.Data)
		return commValue
	}
}

func (e *DatasourceEvent) GetContainer() string {
	containerName, _ := e.getFieldAccessor("k8s.containerName").String(e.Data)
	return containerName
}

func (e *DatasourceEvent) GetContainerID() string {
	containerId, _ := e.getFieldAccessor("runtime.containerId").String(e.Data)
	return containerId
}

func (e *DatasourceEvent) GetContainerImage() string {
	containerImageName, _ := e.getFieldAccessor("runtime.containerImageName").String(e.Data)
	return containerImageName
}

func (e *DatasourceEvent) GetContainerImageDigest() string {
	containerImageDigest, _ := e.getFieldAccessor("runtime.containerImageDigest").String(e.Data)
	return containerImageDigest
}

func (e *DatasourceEvent) GetCwd() string {
	switch e.EventType {
	case ExecveEventType, DnsEventType:
		cwd, _ := e.getFieldAccessor("cwd").String(e.Data)
		return cwd
	default:
		logger.L().Warning("GetCwd not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetDirection() consts.NetworkDirection {
	return e.Direction
}

func (e *DatasourceEvent) GetDNSName() string {
	switch e.EventType {
	case DnsEventType:
		dnsName, _ := e.getFieldAccessor("name").String(e.Data)
		return dnsName
	default:
		logger.L().Warning("GetDNSName not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetDstEndpoint() types.L4Endpoint {
	switch e.EventType {
	case NetworkEventType:
		addr, _ := e.getFieldAccessor("endpoint.addr_raw.v4").Uint32(e.Data)
		kind, _ := e.getFieldAccessor("endpoint.k8s.kind").String(e.Data)
		name, _ := e.getFieldAccessor("endpoint.k8s.name").String(e.Data)
		namespace, _ := e.getFieldAccessor("endpoint.k8s.namespace").String(e.Data)
		podLabels, _ := e.getFieldAccessor("endpoint.k8s.labels").String(e.Data)
		version, _ := e.getFieldAccessor("endpoint.version").Uint8(e.Data)
		port, _ := e.getFieldAccessor("endpoint.port").Uint16(e.Data)
		proto, _ := e.getFieldAccessor("endpoint.proto_raw").Uint16(e.Data)
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
		logger.L().Warning("GetDstEndpoint not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return types.L4Endpoint{}
	}
}

func (e *DatasourceEvent) GetDstIP() string {
	switch e.EventType {
	case DnsEventType, HTTPEventType, SSHEventType:
		version, _ := e.getFieldAccessor("dst.version").Uint8(e.Data)
		switch version {
		case 4:
			daddr, _ := e.getFieldAccessor("dst.addr_raw.v4").Uint32(e.Data)
			return rawIPv4ToString(daddr)
		case 6:
			daddr, _ := e.getFieldAccessor("dst.addr_raw.v6").Bytes(e.Data)
			return rawIPv6ToString(daddr)
		}
	}
	return ""
}

func (e *DatasourceEvent) GetDstPort() uint16 {
	switch e.EventType {
	case NetworkEventType:
		port, _ := e.getFieldAccessor("endpoint.port").Uint16(e.Data)
		return port
	case DnsEventType, HTTPEventType, SSHEventType:
		port, _ := e.getFieldAccessor("dst.port").Uint16(e.Data)
		return port
	default:
		logger.L().Warning("GetDstPort not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetError() int64 {
	err, _ := e.getFieldAccessor("error_raw").Int64(e.Data)
	return err
}

func (e *DatasourceEvent) GetEventType() EventType {
	return e.EventType
}

func (e *DatasourceEvent) GetExePath() string {
	switch e.EventType {
	case DnsEventType, ExecveEventType, ForkEventType, PtraceEventType, RandomXEventType, KmodEventType, UnshareEventType, BpfEventType:
		exepath, _ := e.getFieldAccessor("exepath").String(e.Data)
		return exepath
	default:
		logger.L().Warning("GetExePath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetExitCode() uint32 {
	switch e.EventType {
	case ExitEventType:
		exitCode, _ := e.getFieldAccessor("exit_code").Uint32(e.Data)
		return exitCode
	default:
		logger.L().Warning("GetExitCode not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetExtra() interface{} {
	return e.extra
}

func (e *DatasourceEvent) GetFlags() []string {
	switch e.EventType {
	case OpenEventType:
		flags, _ := e.getFieldAccessor("flags_raw").Int32(e.Data)
		return decodeOpenFlags(flags)
	default:
		logger.L().Warning("GetFlags not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *DatasourceEvent) GetFlagsRaw() uint32 {
	switch e.EventType {
	case OpenEventType:
		flags, _ := e.getFieldAccessor("flags_raw").Int32(e.Data)
		return uint32(flags)
	default:
		logger.L().Warning("GetFlagsRaw not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetFullPath() string {
	switch e.EventType {
	case OpenEventType:
		path, _ := e.getFieldAccessor("fpath").String(e.Data)
		if path == "" {
			path, _ = e.getFieldAccessor("fname").String(e.Data)
		}
		return path
	default:
		logger.L().Warning("GetFullPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetGid() *uint32 {
	switch e.EventType {
	case CapabilitiesEventType, DnsEventType, ExecveEventType, ExitEventType, ForkEventType, HTTPEventType, NetworkEventType, OpenEventType, KmodEventType, UnshareEventType, BpfEventType:
		gid, err := e.getFieldAccessor("proc.creds.gid").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetGid - proc.creds.gid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return nil
		}
		return &gid
	default:
		logger.L().Warning("GetGid not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *DatasourceEvent) GetHostNetwork() bool {
	hostNetwork, _ := e.getFieldAccessor("k8s.hostnetwork").Bool(e.Data)
	return hostNetwork
}

func (e *DatasourceEvent) GetIdentifier() string {
	switch e.EventType {
	case IoUringEventType:
		identifier, _ := e.getFieldAccessor("identifier").String(e.Data)
		return identifier
	default:
		logger.L().Warning("GetIdentifier not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetInternal() bool {
	return e.Internal
}

func (e *DatasourceEvent) GetModule() string {
	switch e.EventType {
	case KmodEventType:
		module, _ := e.getFieldAccessor("module").String(e.Data)
		return module
	default:
		logger.L().Warning("GetModule not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetMountNsID() uint64 {
	mountNsID, _ := e.getFieldAccessor("proc.mntns_id").Uint64(e.Data)
	return mountNsID
}

func (e *DatasourceEvent) GetNamespace() string {
	namespace, _ := e.getFieldAccessor("k8s.namespace").String(e.Data)
	return namespace
}

func (e *DatasourceEvent) GetNewPath() string {
	switch e.EventType {
	case HardlinkEventType, SymlinkEventType:
		newPath, _ := e.getFieldAccessor("newpath").String(e.Data)
		return newPath
	default:
		logger.L().Warning("GetNewPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetNumAnswers() int {
	switch e.EventType {
	case DnsEventType:
		numAnswers, _ := e.getFieldAccessor("num_answers").Int32(e.Data)
		return int(numAnswers)
	default:
		logger.L().Warning("GetNumAnswers not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetOldPath() string {
	switch e.EventType {
	case HardlinkEventType, SymlinkEventType:
		oldPath, _ := e.getFieldAccessor("oldpath").String(e.Data)
		return oldPath
	default:
		logger.L().Warning("GetOldPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetOpcode() int {
	switch e.EventType {
	case IoUringEventType:
		opcode, _ := e.getFieldAccessor("opcode").Int32(e.Data)
		return int(opcode)
	default:
		logger.L().Warning("GetOpcode not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetOtherIp() string {
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

func (e *DatasourceEvent) GetPath() string {
	if e.FullPathTracing {
		return e.GetFullPath()
	}
	switch e.EventType {
	case OpenEventType:
		path, _ := e.getFieldAccessor("fname").String(e.Data)
		return path
	default:
		logger.L().Warning("GetPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetPcomm() string {
	pcomm, _ := e.getFieldAccessor("proc.parent.comm").String(e.Data)
	return pcomm
}

func (e *DatasourceEvent) GetPID() uint32 {
	switch e.EventType {
	case ForkEventType:
		childPid, _ := e.getFieldAccessor("child_pid").Uint32(e.Data)
		return childPid
	case ExitEventType:
		exitPid, _ := e.getFieldAccessor("exit_pid").Uint32(e.Data)
		return exitPid
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		containerPid, _ := e.getFieldAccessor("runtime.containerPid").Uint32(e.Data)
		return containerPid
	case KubeletTLSEventType:
		pidValue, _ := e.getFieldAccessor("pid").Uint32(e.Data)
		return pidValue
	default:
		pidValue, _ := e.getFieldAccessor("proc.pid").Uint32(e.Data)
		return pidValue
	}
}

// GetPID64 is a special implementation for stack trace events.
func (e *DatasourceEvent) GetPID64() uint64 {
	switch e.EventType {
	case ExecveEventType:
		return (uint64(e.GetPpid()) << 32) | e.getPtid()
	case OpenEventType, ExitEventType, ForkEventType, HardlinkEventType, SymlinkEventType:
		return (uint64(e.GetPID()) << 32) | e.getTid()
	default:
		logger.L().Warning("GetPID64 not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetPktType() string {
	egress, _ := e.getFieldAccessor("egress").Uint8(e.Data)
	if egress == 1 {
		return OutgoingPktType
	}
	return HostPktType
}

func (e *DatasourceEvent) GetPod() string {
	podName, _ := e.getFieldAccessor("k8s.podName").String(e.Data)
	return podName
}

func (e *DatasourceEvent) GetPodHostIP() string {
	switch e.EventType {
	case NetworkEventType:
		hostIP, _ := e.getFieldAccessor("k8s.hostIP").String(e.Data)
		return hostIP
	default:
		logger.L().Warning("GetPodHostIP not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetPodLabels() map[string]string {
	podLabels, _ := e.getFieldAccessor("k8s.podLabels").String(e.Data)
	return parseStringToMap(podLabels)
}

func (e *DatasourceEvent) GetPpid() uint32 {
	switch e.EventType {
	case ForkEventType:
		parentPid, _ := e.getFieldAccessor("parent_pid").Uint32(e.Data)
		return parentPid
	case ExitEventType:
		exitPpid, _ := e.getFieldAccessor("exit_ppid").Uint32(e.Data)
		return exitPpid
	default:
		ppid, _ := e.getFieldAccessor("proc.parent.pid").Uint32(e.Data)
		return ppid
	}
}

func (e *DatasourceEvent) GetProto() string {
	switch e.EventType {
	case DnsEventType:
		protoNum, _ := e.getFieldAccessor("dst.proto_raw").Uint16(e.Data)
		return protoNumToString(protoNum)
	case NetworkEventType:
		protoNum, _ := e.getFieldAccessor("endpoint.proto_raw").Uint16(e.Data)
		return protoNumToString(protoNum)
	default:
		logger.L().Warning("GetProto not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) getPtid() uint64 {
	ptid, _ := e.getFieldAccessor("proc.parent.tid").Uint32(e.Data)
	return uint64(ptid)
}

func (e *DatasourceEvent) GetPupperLayer() bool {
	switch e.EventType {
	case ExecveEventType:
		pupperLayer, _ := e.getFieldAccessor("pupper_layer").Bool(e.Data)
		return pupperLayer
	default:
		logger.L().Warning("GetPupperLayer not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
}

func (e *DatasourceEvent) GetQr() DNSPktType {
	switch e.EventType {
	case DnsEventType:
		isResponse, _ := e.getFieldAccessor("qr_raw").Bool(e.Data)
		if isResponse {
			return DNSPktTypeResponse
		}
		return DNSPktTypeQuery
	default:
		logger.L().Warning("GetQr not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetRequest() *http.Request {
	return e.Request
}

func (e *DatasourceEvent) GetResponse() *http.Response {
	return e.Response
}

func (e *DatasourceEvent) GetSignal() uint32 {
	switch e.EventType {
	case ExitEventType:
		signal, _ := e.getFieldAccessor("exit_signal").Uint32(e.Data)
		return signal
	default:
		logger.L().Warning("GetSignal not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetSocketInode() uint64 {
	switch e.EventType {
	case HTTPEventType:
		socketInode, _ := e.getFieldAccessor("socket_inode").Uint64(e.Data)
		return socketInode
	default:
		logger.L().Warning("GetSocketInode not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetSockFd() uint32 {
	switch e.EventType {
	case HTTPEventType:
		sockFd, _ := e.getFieldAccessor("sock_fd").Uint32(e.Data)
		return sockFd
	default:
		logger.L().Warning("GetSockFd not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetSrcIP() string {
	switch e.EventType {
	case DnsEventType, HTTPEventType, SSHEventType:
		version, _ := e.getFieldAccessor("src.version").Uint8(e.Data)
		switch version {
		case 4:
			addr, _ := e.getFieldAccessor("src.addr_raw.v4").Uint32(e.Data)
			return rawIPv4ToString(addr)
		case 6:
			addr, _ := e.getFieldAccessor("src.addr_raw.v6").Bytes(e.Data)
			return rawIPv6ToString(addr)
		}
	}
	return ""
}

func (e *DatasourceEvent) GetSrcPort() uint16 {
	switch e.EventType {
	case DnsEventType, HTTPEventType, SSHEventType:
		port, _ := e.getFieldAccessor("src.port").Uint16(e.Data)
		return port
	default:
		logger.L().Warning("GetSrcPort not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetSyscall() string {
	switch e.EventType {
	case CapabilitiesEventType:
		syscallRaw, _ := e.getFieldAccessor("syscall_raw").Uint16(e.Data)
		return syscalls.SyscallGetName(syscallRaw)
	case HTTPEventType:
		syscall, _ := e.getFieldAccessor("syscall").Bytes(e.Data)
		return gadgets.FromCString(syscall)
	case SyscallEventType:
		return e.Syscall
	case KmodEventType:
		syscall, _ := e.getFieldAccessor("syscall").String(e.Data)
		return syscall
	default:
		logger.L().Warning("GetSyscall not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetSyscalls() []byte {
	switch e.EventType {
	case SyscallEventType:
		syscallsBuffer, _ := e.getFieldAccessor("syscalls").Bytes(e.Data)
		return syscallsBuffer
	default:
		logger.L().Warning("GetSyscalls not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *DatasourceEvent) getTid() uint64 {
	switch e.EventType {
	case ExitEventType:
		tid, _ := e.getFieldAccessor("exit_tid").Uint32(e.Data)
		return uint64(tid)
	default:
		tid, _ := e.getFieldAccessor("proc.tid").Uint32(e.Data)
		return uint64(tid)
	}
}

func (e *DatasourceEvent) GetTimestamp() types.Time {
	switch e.EventType {
	case SyscallEventType:
		return types.Time(time.Now().UnixNano())
	default:
		timeStampRaw, _ := e.getFieldAccessor("timestamp_raw").Uint64(e.Data)
		return gadgets.WallTimeFromBootTime(timeStampRaw)
	}
}

func (e *DatasourceEvent) GetTLSData() string {
	switch e.EventType {
	case KubeletTLSEventType:
		data, _ := e.getFieldAccessor("data").String(e.Data)
		return data
	default:
		logger.L().Warning("GetTLSData not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetTLSDataLen() int32 {
	switch e.EventType {
	case KubeletTLSEventType:
		dataLen, _ := e.getFieldAccessor("data_len").Int32(e.Data)
		return dataLen
	default:
		logger.L().Warning("GetTLSDataLen not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetTLSEventType() uint8 {
	switch e.EventType {
	case KubeletTLSEventType:
		eventType, _ := e.getFieldAccessor("event_type").Uint8(e.Data)
		return eventType
	default:
		logger.L().Warning("GetTLSEventType not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetType() HTTPDataType {
	switch e.EventType {
	case HTTPEventType:
		t, _ := e.getFieldAccessor("type").Uint8(e.Data)
		return HTTPDataType(t)
	default:
		logger.L().Warning("GetType not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetUid() *uint32 {
	switch e.EventType {
	case CapabilitiesEventType, DnsEventType, ExecveEventType, ExitEventType, ForkEventType, HTTPEventType, NetworkEventType, OpenEventType, KmodEventType, UnshareEventType, BpfEventType:
		uid, err := e.getFieldAccessor("proc.creds.uid").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetUid - proc.creds.uid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return nil
		}
		return &uid
	default:
		logger.L().Warning("GetUid not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *DatasourceEvent) GetUpperLayer() bool {
	switch e.EventType {
	case ExecveEventType, SymlinkEventType, HardlinkEventType, ExitEventType, RandomXEventType, KmodEventType, UnshareEventType, BpfEventType:
		upperLayer, _ := e.getFieldAccessor("upper_layer").Bool(e.Data)
		return upperLayer
	default:
		logger.L().Warning("GetUpperLayer not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
}

func (e *DatasourceEvent) HasDroppedEvents() bool {
	if e.Data.LostSampleCount() > 0 {
		return true
	}
	return false
}

func (e *DatasourceEvent) IsDir() bool {
	switch e.EventType {
	case OpenEventType:
		raw, _ := e.getFieldAccessor("mode_raw").Uint32(e.Data)
		fileMode := os.FileMode(raw)
		return fileMode.IsDir()
	default:
		logger.L().Warning("IsDir not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
}

func (e *DatasourceEvent) MakeHttpEvent(request *http.Request, direction consts.NetworkDirection) HttpEvent {
	return &DatasourceEvent{
		Data:       e.Data,
		Datasource: e.Datasource,
		Direction:  direction,
		EventType:  e.EventType,
		Internal:   func() bool { ip := net.ParseIP(e.GetOtherIp()); return ip != nil && ip.IsPrivate() }(),
		Request:    request,
		Response:   e.Response,
		Syscall:    e.Syscall,
		extra:      e.extra,
	}
}

func (e *DatasourceEvent) Release() {
	e.Datasource.Release(e.Data)
}

func (e *DatasourceEvent) SetExtra(extra interface{}) {
	e.extra = extra
}

func (e *DatasourceEvent) SetResponse(response *http.Response) {
	e.Response = response
}

// ECS-specific methods - implementing EnrichEvent interface
func (e *DatasourceEvent) GetEcsClusterName() string {
	clusterName, _ := e.getFieldAccessor("ecs.clusterName").String(e.Data)
	return clusterName
}

func (e *DatasourceEvent) GetEcsClusterARN() string {
	clusterARN, _ := e.getFieldAccessor("ecs.clusterARN").String(e.Data)
	return clusterARN
}

func (e *DatasourceEvent) GetEcsTaskARN() string {
	taskARN, _ := e.getFieldAccessor("ecs.taskARN").String(e.Data)
	return taskARN
}

func (e *DatasourceEvent) GetEcsTaskFamily() string {
	taskFamily, _ := e.getFieldAccessor("ecs.taskFamily").String(e.Data)
	return taskFamily
}

func (e *DatasourceEvent) GetEcsTaskDefinitionARN() string {
	taskDefARN, _ := e.getFieldAccessor("ecs.taskDefinitionARN").String(e.Data)
	return taskDefARN
}

func (e *DatasourceEvent) GetEcsServiceName() string {
	serviceName, _ := e.getFieldAccessor("ecs.serviceName").String(e.Data)
	return serviceName
}

func (e *DatasourceEvent) GetEcsContainerName() string {
	containerName, _ := e.getFieldAccessor("ecs.containerName").String(e.Data)
	return containerName
}

func (e *DatasourceEvent) GetEcsContainerARN() string {
	containerARN, _ := e.getFieldAccessor("ecs.containerARN").String(e.Data)
	return containerARN
}

func (e *DatasourceEvent) GetEcsContainerInstance() string {
	containerInstance, _ := e.getFieldAccessor("ecs.containerInstance").String(e.Data)
	return containerInstance
}

func (e *DatasourceEvent) GetEcsAvailabilityZone() string {
	availabilityZone, _ := e.getFieldAccessor("ecs.availabilityZone").String(e.Data)
	return availabilityZone
}

func (e *DatasourceEvent) GetEcsLaunchType() string {
	launchType, _ := e.getFieldAccessor("ecs.launchType").String(e.Data)
	return launchType
}
