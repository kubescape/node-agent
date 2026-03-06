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
		if field == nil {
			logger.L().Warning("field not found", helpers.String("field", fieldName), helpers.String("eventType", string(e.EventType)))
			// Don't cache nil results - another data source may have this field
			return missingFieldAccessor
		}
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

func (e *DatasourceEvent) GetAddresses() []string {
	addresses, _ := e.getFieldAccessor("addresses").String(e.Data)
	if addresses == "" {
		return nil
	}
	return strings.Split(addresses, ",")
}

func (e *DatasourceEvent) GetArgs() []string {
	args, _ := e.getFieldAccessor("args").String(e.Data)
	if args == "" {
		return nil
	}
	return strings.Split(args, igconsts.ArgsSeparator)
}

func (e *DatasourceEvent) GetAttrSize() uint32 {
	attrSize, _ := e.getFieldAccessor("attr_size").Uint32(e.Data)
	return attrSize
}

func (e *DatasourceEvent) GetBuf() []byte {
	buf, _ := e.getFieldAccessor("buf").Bytes(e.Data)
	return buf
}

func (e *DatasourceEvent) GetBufLen() uint16 {
	bufLen, err := e.getFieldAccessor("buf_len").Uint16(e.Data)
	if err != nil {
		return 0
	}
	return bufLen
}

func (e *DatasourceEvent) GetCapability() string {
	capability, _ := e.getFieldAccessor("cap").String(e.Data)
	return capability
}

func (e *DatasourceEvent) GetCmd() uint32 {
	cmd, _ := e.getFieldAccessor("cmd").Uint32(e.Data)
	return cmd
}

func (e *DatasourceEvent) GetComm() string {
	switch e.EventType {
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		container := e.GetContainer()
		return container
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
	cwd, _ := e.getFieldAccessor("cwd").String(e.Data)
	return cwd
}

func (e *DatasourceEvent) GetDirection() consts.NetworkDirection {
	return e.Direction
}

func (e *DatasourceEvent) GetDNSName() string {
	dnsName, _ := e.getFieldAccessor("name").String(e.Data)
	return dnsName
}

func (e *DatasourceEvent) GetDstEndpoint() types.L4Endpoint {
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
}

func (e *DatasourceEvent) GetDstIP() string {
	version, _ := e.getFieldAccessor("dst.version").Uint8(e.Data)
	switch version {
	case 4:
		daddr, _ := e.getFieldAccessor("dst.addr_raw.v4").Uint32(e.Data)
		return rawIPv4ToString(daddr)
	case 6:
		daddr, _ := e.getFieldAccessor("dst.addr_raw.v6").Bytes(e.Data)
		return rawIPv6ToString(daddr)
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

func (e *DatasourceEvent) GetEcsAvailabilityZone() string {
	availabilityZone, _ := e.getFieldAccessor("ecs.availabilityZone").String(e.Data)
	return availabilityZone
}

func (e *DatasourceEvent) GetEcsClusterARN() string {
	clusterARN, _ := e.getFieldAccessor("ecs.clusterARN").String(e.Data)
	return clusterARN
}

func (e *DatasourceEvent) GetEcsClusterName() string {
	clusterName, _ := e.getFieldAccessor("ecs.clusterName").String(e.Data)
	return clusterName
}

func (e *DatasourceEvent) GetEcsContainerARN() string {
	containerARN, _ := e.getFieldAccessor("ecs.containerARN").String(e.Data)
	return containerARN
}

func (e *DatasourceEvent) GetEcsContainerInstance() string {
	containerInstance, _ := e.getFieldAccessor("ecs.containerInstance").String(e.Data)
	return containerInstance
}

func (e *DatasourceEvent) GetEcsContainerName() string {
	containerName, _ := e.getFieldAccessor("ecs.containerName").String(e.Data)
	return containerName
}

func (e *DatasourceEvent) GetEcsLaunchType() string {
	launchType, _ := e.getFieldAccessor("ecs.launchType").String(e.Data)
	return launchType
}

func (e *DatasourceEvent) GetEcsServiceName() string {
	serviceName, _ := e.getFieldAccessor("ecs.serviceName").String(e.Data)
	return serviceName
}

func (e *DatasourceEvent) GetEcsTaskARN() string {
	taskARN, _ := e.getFieldAccessor("ecs.taskARN").String(e.Data)
	return taskARN
}

func (e *DatasourceEvent) GetEcsTaskDefinitionARN() string {
	taskDefARN, _ := e.getFieldAccessor("ecs.taskDefinitionARN").String(e.Data)
	return taskDefARN
}

func (e *DatasourceEvent) GetEcsTaskFamily() string {
	taskFamily, _ := e.getFieldAccessor("ecs.taskFamily").String(e.Data)
	return taskFamily
}

func (e *DatasourceEvent) GetError() int64 {
	errVal, _ := e.getFieldAccessor("error_raw").Int32(e.Data)
	return int64(errVal)
}

func (e *DatasourceEvent) GetEventType() EventType {
	return e.EventType
}

func (e *DatasourceEvent) GetExePath() string {
	exepath, err := e.getFieldAccessor("exepath").String(e.Data)
	if err != nil {
		logger.L().Warning("GetExePath - error reading field exepath", helpers.String("eventType", string(e.EventType)), helpers.Error(err))
		return ""
	}
	return NormalizePath(exepath)
}

func (e *DatasourceEvent) GetExitCode() uint32 {
	exitCode, _ := e.getFieldAccessor("exit_code").Uint32(e.Data)
	return exitCode
}

func (e *DatasourceEvent) GetExtra() interface{} {
	return e.extra
}

func (e *DatasourceEvent) GetFlags() []string {
	flags, _ := e.getFieldAccessor("flags_raw").Int32(e.Data)
	return decodeOpenFlags(flags)
}

func (e *DatasourceEvent) GetFlagsRaw() uint32 {
	flags, _ := e.getFieldAccessor("flags_raw").Int32(e.Data)
	return uint32(flags)
}

func (e *DatasourceEvent) GetFullPath() string {
	path, _ := e.getFieldAccessor("fpath").String(e.Data)
	if path == "" {
		path, _ = e.getFieldAccessor("fname").String(e.Data)
	}
	return NormalizePath(path)
}

func (e *DatasourceEvent) GetGid() *uint32 {
	switch e.EventType {
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		return nil
	default:
		gid, _ := e.getFieldAccessor("proc.creds.gid").Uint32(e.Data)
		return &gid
	}
}

func (e *DatasourceEvent) GetHostNetwork() bool {
	hostNetwork, _ := e.getFieldAccessor("k8s.hostnetwork").Bool(e.Data)
	return hostNetwork
}

func (e *DatasourceEvent) GetIdentifier() string {
	identifier, _ := e.getFieldAccessor("identifier").String(e.Data)
	return identifier
}

func (e *DatasourceEvent) GetInternal() bool {
	return e.Internal
}

func (e *DatasourceEvent) GetModule() string {
	module, _ := e.getFieldAccessor("module").String(e.Data)
	return module
}

func (e *DatasourceEvent) GetMountNsID() uint64 {
	switch e.EventType {
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		return 0
	default:
		mountNsID, _ := e.getFieldAccessor("proc.mntns_id").Uint64(e.Data)
		return mountNsID
	}
}

func (e *DatasourceEvent) GetNamespace() string {
	namespace, _ := e.getFieldAccessor("k8s.namespace").String(e.Data)
	return namespace
}

func (e *DatasourceEvent) GetNewPath() string {
	newPath, err := e.getFieldAccessor("newpath").String(e.Data)
	if err != nil {
		logger.L().Warning("GetNewPath - error reading field newpath", helpers.String("eventType", string(e.EventType)), helpers.Error(err))
		return ""
	}
	return NormalizePath(newPath)
}

func (e *DatasourceEvent) GetNumAnswers() int {
	numAnswers, _ := e.getFieldAccessor("num_answers").Int32(e.Data)
	return int(numAnswers)
}

func (e *DatasourceEvent) GetOldPath() string {
	oldPath, err := e.getFieldAccessor("oldpath").String(e.Data)
	if err != nil {
		logger.L().Warning("GetOldPath - error reading field oldpath", helpers.String("eventType", string(e.EventType)), helpers.Error(err))
		return ""
	}
	return NormalizePath(oldPath)
}

func (e *DatasourceEvent) GetOpcode() int {
	opcode, _ := e.getFieldAccessor("opcode").Int32(e.Data)
	return int(opcode)
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
	path, err := e.getFieldAccessor("fname").String(e.Data)
	if err != nil {
		logger.L().Warning("GetPath - error reading field fname", helpers.String("eventType", string(e.EventType)), helpers.Error(err))
		return ""
	}
	return NormalizePath(path)
}

func (e *DatasourceEvent) GetPcomm() string {
	switch e.EventType {
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		return ""
	default:
		pcomm, _ := e.getFieldAccessor("proc.parent.comm").String(e.Data)
		return pcomm
	}
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
		return 0
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

func (e *DatasourceEvent) getPtid() uint64 {
	switch e.EventType {
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		return 0
	default:
		ptid, _ := e.getFieldAccessor("proc.parent.tid").Uint32(e.Data)
		return uint64(ptid)
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
	hostIP, _ := e.getFieldAccessor("k8s.hostIP").String(e.Data)
	return hostIP
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
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		return 0
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

func (e *DatasourceEvent) GetPupperLayer() bool {
	pupperLayer, _ := e.getFieldAccessor("pupper_layer").Bool(e.Data)
	return pupperLayer
}

func (e *DatasourceEvent) GetQr() DNSPktType {
	isResponse, _ := e.getFieldAccessor("qr_raw").Bool(e.Data)
	if isResponse {
		return DNSPktTypeResponse
	}
	return DNSPktTypeQuery
}

func (e *DatasourceEvent) GetRequest() *http.Request {
	return e.Request
}

func (e *DatasourceEvent) GetResponse() *http.Response {
	return e.Response
}

func (e *DatasourceEvent) GetSignal() uint32 {
	signal, _ := e.getFieldAccessor("exit_signal").Uint32(e.Data)
	return signal
}

func (e *DatasourceEvent) GetSocketInode() uint64 {
	socketInode, _ := e.getFieldAccessor("socket_inode").Uint64(e.Data)
	return socketInode
}

func (e *DatasourceEvent) GetSockFd() uint32 {
	sockFd, _ := e.getFieldAccessor("sock_fd").Uint32(e.Data)
	return sockFd
}

func (e *DatasourceEvent) GetSrcIP() string {
	version, _ := e.getFieldAccessor("src.version").Uint8(e.Data)
	switch version {
	case 4:
		addr, _ := e.getFieldAccessor("src.addr_raw.v4").Uint32(e.Data)
		return rawIPv4ToString(addr)
	case 6:
		addr, _ := e.getFieldAccessor("src.addr_raw.v6").Bytes(e.Data)
		return rawIPv6ToString(addr)
	}
	return ""
}

func (e *DatasourceEvent) GetSrcPort() uint16 {
	port, _ := e.getFieldAccessor("src.port").Uint16(e.Data)
	return port
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
	syscallsBuffer, _ := e.getFieldAccessor("syscalls").Bytes(e.Data)
	return syscallsBuffer
}

func (e *DatasourceEvent) getTid() uint64 {
	switch e.EventType {
	case ExitEventType:
		tid, _ := e.getFieldAccessor("exit_tid").Uint32(e.Data)
		return uint64(tid)
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		return 0
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

func (e *DatasourceEvent) GetType() HTTPDataType {
	t, _ := e.getFieldAccessor("type").Uint8(e.Data)
	return HTTPDataType(t)
}

func (e *DatasourceEvent) GetUid() *uint32 {
	switch e.EventType {
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		return nil
	default:
		uid, _ := e.getFieldAccessor("proc.creds.uid").Uint32(e.Data)
		return &uid
	}
}

func (e *DatasourceEvent) GetUpperLayer() bool {
	upperLayer, _ := e.getFieldAccessor("upper_layer").Bool(e.Data)
	return upperLayer
}

func (e *DatasourceEvent) HasDroppedEvents() bool {
	if e.Data.LostSampleCount() > 0 {
		return true
	}
	return false
}

func (e *DatasourceEvent) IsDir() bool {
	raw, _ := e.getFieldAccessor("mode_raw").Uint32(e.Data)
	fileMode := os.FileMode(raw)
	return fileMode.IsDir()
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
