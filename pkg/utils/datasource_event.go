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
	addresses, err := e.getFieldAccessor("addresses").String(e.Data)
	if err != nil {
		logger.L().Warning("GetAddresses - addresses field not found in event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
	return strings.Split(addresses, ",")
}

func (e *DatasourceEvent) GetArgs() []string {
	args, err := e.getFieldAccessor("args").String(e.Data)
	if err != nil {
		logger.L().Warning("GetArgs - args field not found in event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
	return strings.Split(args, igconsts.ArgsSeparator)
}

func (e *DatasourceEvent) GetAttrSize() uint32 {
	attrSize, err := e.getFieldAccessor("attr_size").Uint32(e.Data)
	if err != nil {
		logger.L().Warning("GetAttrSize - attr_size field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return attrSize
}

func (e *DatasourceEvent) GetBuf() []byte {
	buf, err := e.getFieldAccessor("buf").Bytes(e.Data)
	if err != nil {
		logger.L().Warning("GetBuf - buf field not found in event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
	return buf
}

func (e *DatasourceEvent) GetCapability() string {
	capability, err := e.getFieldAccessor("cap").String(e.Data)
	if err != nil {
		logger.L().Warning("GetCapability - cap field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return capability
}

func (e *DatasourceEvent) GetCmd() uint32 {
	cmd, err := e.getFieldAccessor("cmd").Uint32(e.Data)
	if err != nil {
		logger.L().Warning("GetCmd - cmd field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return cmd
}

func (e *DatasourceEvent) GetComm() string {
	switch e.EventType {
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		container := e.GetContainer()
		return container
	default:
		commValue, err := e.getFieldAccessor("proc.comm").String(e.Data)
		if err != nil {
			logger.L().Warning("GetComm - proc.comm field not found in event type", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		return commValue
	}
}

func (e *DatasourceEvent) GetContainer() string {
	containerName, err := e.getFieldAccessor("k8s.containerName").String(e.Data)
	if err != nil {
		logger.L().Warning("GetContainer - k8s.containerName field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return containerName
}

func (e *DatasourceEvent) GetContainerID() string {
	containerId, err := e.getFieldAccessor("runtime.containerId").String(e.Data)
	if err != nil {
		logger.L().Warning("GetContainerID - runtime.containerId field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return containerId
}

func (e *DatasourceEvent) GetContainerImage() string {
	containerImageName, err := e.getFieldAccessor("runtime.containerImageName").String(e.Data)
	if err != nil {
		logger.L().Warning("GetContainerImage - runtime.containerImageName field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return containerImageName
}

func (e *DatasourceEvent) GetContainerImageDigest() string {
	containerImageDigest, err := e.getFieldAccessor("runtime.containerImageDigest").String(e.Data)
	if err != nil {
		logger.L().Warning("GetContainerImageDigest - runtime.containerImageDigest field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return containerImageDigest
}

func (e *DatasourceEvent) GetCwd() string {
	cwd, err := e.getFieldAccessor("cwd").String(e.Data)
	if err != nil {
		logger.L().Warning("GetCwd - cwd field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return cwd
}

func (e *DatasourceEvent) GetDirection() consts.NetworkDirection {
	return e.Direction
}

func (e *DatasourceEvent) GetDNSName() string {
	dnsName, err := e.getFieldAccessor("name").String(e.Data)
	if err != nil {
		logger.L().Warning("GetDNSName - name field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return dnsName
}

func (e *DatasourceEvent) GetDstEndpoint() types.L4Endpoint {
	addr, err := e.getFieldAccessor("endpoint.addr_raw.v4").Uint32(e.Data)
	if err != nil {
		logger.L().Warning("GetDstEndpoint - endpoint.addr_raw.v4 field not found in event type", helpers.String("eventType", string(e.EventType)))
		return types.L4Endpoint{}
	}
	kind, err := e.getFieldAccessor("endpoint.k8s.kind").String(e.Data)
	if err != nil {
		logger.L().Warning("GetDstEndpoint - endpoint.k8s.kind field not found in event type", helpers.String("eventType", string(e.EventType)))
		return types.L4Endpoint{}
	}
	name, err := e.getFieldAccessor("endpoint.k8s.name").String(e.Data)
	if err != nil {
		logger.L().Warning("GetDstEndpoint - endpoint.k8s.name field not found in event type", helpers.String("eventType", string(e.EventType)))
		return types.L4Endpoint{}
	}
	namespace, err := e.getFieldAccessor("endpoint.k8s.namespace").String(e.Data)
	if err != nil {
		logger.L().Warning("GetDstEndpoint - endpoint.k8s.namespace field not found in event type", helpers.String("eventType", string(e.EventType)))
		return types.L4Endpoint{}
	}
	podLabels, err := e.getFieldAccessor("endpoint.k8s.labels").String(e.Data)
	if err != nil {
		logger.L().Warning("GetDstEndpoint - endpoint.k8s.labels field not found in event type", helpers.String("eventType", string(e.EventType)))
		return types.L4Endpoint{}
	}
	version, err := e.getFieldAccessor("endpoint.version").Uint8(e.Data)
	if err != nil {
		logger.L().Warning("GetDstEndpoint - endpoint.version field not found in event type", helpers.String("eventType", string(e.EventType)))
		return types.L4Endpoint{}
	}
	port, err := e.getFieldAccessor("endpoint.port").Uint16(e.Data)
	if err != nil {
		logger.L().Warning("GetDstEndpoint - endpoint.port field not found in event type", helpers.String("eventType", string(e.EventType)))
		return types.L4Endpoint{}
	}
	proto, err := e.getFieldAccessor("endpoint.proto_raw").Uint16(e.Data)
	if err != nil {
		logger.L().Warning("GetDstEndpoint - endpoint.proto_raw field not found in event type", helpers.String("eventType", string(e.EventType)))
		return types.L4Endpoint{}
	}
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
	version, err := e.getFieldAccessor("dst.version").Uint8(e.Data)
	if err != nil {
		logger.L().Warning("GetDstIP - dst.version field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	switch version {
	case 4:
		daddr, err := e.getFieldAccessor("dst.addr_raw.v4").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetDstIP - dst.addr_raw.v4 field not found in event type", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		return rawIPv4ToString(daddr)
	case 6:
		daddr, err := e.getFieldAccessor("dst.addr_raw.v6").Bytes(e.Data)
		if err != nil {
			logger.L().Warning("GetDstIP - dst.addr_raw.v6 field not found in event type", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		return rawIPv6ToString(daddr)
	}
	return ""
}

func (e *DatasourceEvent) GetDstPort() uint16 {
	switch e.EventType {
	case NetworkEventType:
		port, err := e.getFieldAccessor("endpoint.port").Uint16(e.Data)
		if err != nil {
			logger.L().Warning("GetDstPort - endpoint.port field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		return port
	case DnsEventType, HTTPEventType, SSHEventType:
		port, err := e.getFieldAccessor("dst.port").Uint16(e.Data)
		if err != nil {
			logger.L().Warning("GetDstPort - dst.port field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		return port
	default:
		logger.L().Warning("GetDstPort not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetEcsAvailabilityZone() string {
	availabilityZone, err := e.getFieldAccessor("ecs.availabilityZone").String(e.Data)
	if err != nil {
		logger.L().Warning("GetEcsAvailabilityZone - ecs.availabilityZone field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return availabilityZone
}

func (e *DatasourceEvent) GetEcsClusterARN() string {
	clusterARN, err := e.getFieldAccessor("ecs.clusterARN").String(e.Data)
	if err != nil {
		logger.L().Warning("GetEcsClusterARN - ecs.clusterARN field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return clusterARN
}

func (e *DatasourceEvent) GetEcsClusterName() string {
	clusterName, err := e.getFieldAccessor("ecs.clusterName").String(e.Data)
	if err != nil {
		logger.L().Warning("GetEcsClusterName - ecs.clusterName field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return clusterName
}

func (e *DatasourceEvent) GetEcsContainerARN() string {
	containerARN, err := e.getFieldAccessor("ecs.containerARN").String(e.Data)
	if err != nil {
		logger.L().Warning("GetEcsContainerARN - ecs.containerARN field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return containerARN
}

func (e *DatasourceEvent) GetEcsContainerInstance() string {
	containerInstance, err := e.getFieldAccessor("ecs.containerInstance").String(e.Data)
	if err != nil {
		logger.L().Warning("GetEcsContainerInstance - ecs.containerInstance field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return containerInstance
}

func (e *DatasourceEvent) GetEcsContainerName() string {
	containerName, err := e.getFieldAccessor("ecs.containerName").String(e.Data)
	if err != nil {
		logger.L().Warning("GetEcsContainerName - ecs.containerName field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return containerName
}

func (e *DatasourceEvent) GetEcsLaunchType() string {
	launchType, err := e.getFieldAccessor("ecs.launchType").String(e.Data)
	if err != nil {
		logger.L().Warning("GetEcsLaunchType - ecs.launchType field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return launchType
}

func (e *DatasourceEvent) GetEcsServiceName() string {
	serviceName, err := e.getFieldAccessor("ecs.serviceName").String(e.Data)
	if err != nil {
		logger.L().Warning("GetEcsServiceName - ecs.serviceName field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return serviceName
}

func (e *DatasourceEvent) GetEcsTaskARN() string {
	taskARN, err := e.getFieldAccessor("ecs.taskARN").String(e.Data)
	if err != nil {
		logger.L().Warning("GetEcsTaskARN - ecs.taskARN field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return taskARN
}

func (e *DatasourceEvent) GetEcsTaskDefinitionARN() string {
	taskDefARN, err := e.getFieldAccessor("ecs.taskDefinitionARN").String(e.Data)
	if err != nil {
		logger.L().Warning("GetEcsTaskDefinitionARN - ecs.taskDefinitionARN field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return taskDefARN
}

func (e *DatasourceEvent) GetEcsTaskFamily() string {
	taskFamily, err := e.getFieldAccessor("ecs.taskFamily").String(e.Data)
	if err != nil {
		logger.L().Warning("GetEcsTaskFamily - ecs.taskFamily field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return taskFamily
}

func (e *DatasourceEvent) GetError() int64 {
	errVal, err := e.getFieldAccessor("error_raw").Int64(e.Data)
	if err != nil {
		logger.L().Warning("GetError - error_raw field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return errVal
}

func (e *DatasourceEvent) GetEventType() EventType {
	return e.EventType
}

func (e *DatasourceEvent) GetExePath() string {
	exepath, err := e.getFieldAccessor("exepath").String(e.Data)
	if err != nil {
		logger.L().Warning("GetExePath - exepath field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return exepath
}

func (e *DatasourceEvent) GetExitCode() uint32 {
	exitCode, err := e.getFieldAccessor("exit_code").Uint32(e.Data)
	if err != nil {
		logger.L().Warning("GetExitCode - exit_code field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return exitCode
}

func (e *DatasourceEvent) GetExtra() interface{} {
	return e.extra
}

func (e *DatasourceEvent) GetFlags() []string {
	flags, err := e.getFieldAccessor("flags_raw").Int32(e.Data)
	if err != nil {
		logger.L().Warning("GetFlags - flags_raw field not found in event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
	return decodeOpenFlags(flags)
}

func (e *DatasourceEvent) GetFlagsRaw() uint32 {
	flags, err := e.getFieldAccessor("flags_raw").Int32(e.Data)
	if err != nil {
		logger.L().Warning("GetFlagsRaw - flags_raw field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return uint32(flags)
}

func (e *DatasourceEvent) GetFullPath() string {
	path, err := e.getFieldAccessor("fpath").String(e.Data)
	if err != nil || path == "" {
		path, err = e.getFieldAccessor("fname").String(e.Data)
		if err != nil {
			return ""
		}
	}
	return path
}

func (e *DatasourceEvent) GetGid() *uint32 {
	gid, err := e.getFieldAccessor("proc.creds.gid").Uint32(e.Data)
	if err != nil {
		logger.L().Warning("GetGid - proc.creds.gid field not found in event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
	return &gid
}

func (e *DatasourceEvent) GetHostNetwork() bool {
	hostNetwork, err := e.getFieldAccessor("k8s.hostnetwork").Bool(e.Data)
	if err != nil {
		logger.L().Warning("GetHostNetwork - k8s.hostnetwork field not found in event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
	return hostNetwork
}

func (e *DatasourceEvent) GetIdentifier() string {
	identifier, err := e.getFieldAccessor("identifier").String(e.Data)
	if err != nil {
		logger.L().Warning("GetIdentifier - identifier field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return identifier
}

func (e *DatasourceEvent) GetInternal() bool {
	return e.Internal
}

func (e *DatasourceEvent) GetModule() string {
	module, err := e.getFieldAccessor("module").String(e.Data)
	if err != nil {
		logger.L().Warning("GetModule - module field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return module
}

func (e *DatasourceEvent) GetMountNsID() uint64 {
	mountNsID, err := e.getFieldAccessor("proc.mntns_id").Uint64(e.Data)
	if err != nil {
		logger.L().Warning("GetMountNsID - proc.mntns_id field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return mountNsID
}

func (e *DatasourceEvent) GetNamespace() string {
	namespace, err := e.getFieldAccessor("k8s.namespace").String(e.Data)
	if err != nil {
		logger.L().Warning("GetNamespace - k8s.namespace field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return namespace
}

func (e *DatasourceEvent) GetNewPath() string {
	newPath, err := e.getFieldAccessor("newpath").String(e.Data)
	if err != nil {
		logger.L().Warning("GetNewPath - newpath field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return newPath
}

func (e *DatasourceEvent) GetNumAnswers() int {
	numAnswers, err := e.getFieldAccessor("num_answers").Int32(e.Data)
	if err != nil {
		logger.L().Warning("GetNumAnswers - num_answers field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return int(numAnswers)
}

func (e *DatasourceEvent) GetOldPath() string {
	oldPath, err := e.getFieldAccessor("oldpath").String(e.Data)
	if err != nil {
		logger.L().Warning("GetOldPath - oldpath field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return oldPath
}

func (e *DatasourceEvent) GetOpcode() int {
	opcode, err := e.getFieldAccessor("opcode").Int32(e.Data)
	if err != nil {
		logger.L().Warning("GetOpcode - opcode field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
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
		logger.L().Warning("GetPath - fname field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return path
}

func (e *DatasourceEvent) GetPcomm() string {
	pcomm, err := e.getFieldAccessor("proc.parent.comm").String(e.Data)
	if err != nil {
		logger.L().Warning("GetPcomm - proc.parent.comm field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return pcomm
}

func (e *DatasourceEvent) GetPID() uint32 {
	switch e.EventType {
	case ForkEventType:
		childPid, err := e.getFieldAccessor("child_pid").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetPID - child_pid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		return childPid
	case ExitEventType:
		exitPid, err := e.getFieldAccessor("exit_pid").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetPID - exit_pid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		return exitPid
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		containerPid, err := e.getFieldAccessor("runtime.containerPid").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetPID - runtime.containerPid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		return containerPid
	default:
		pidValue, err := e.getFieldAccessor("proc.pid").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetPID - proc.pid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
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
	ptid, err := e.getFieldAccessor("proc.parent.tid").Uint32(e.Data)
	if err != nil {
		logger.L().Warning("getPtid - proc.parent.tid field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return uint64(ptid)
}

func (e *DatasourceEvent) GetPktType() string {
	egress, err := e.getFieldAccessor("egress").Uint8(e.Data)
	if err != nil {
		logger.L().Warning("GetPktType - egress field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	if egress == 1 {
		return OutgoingPktType
	}
	return HostPktType
}

func (e *DatasourceEvent) GetPod() string {
	podName, err := e.getFieldAccessor("k8s.podName").String(e.Data)
	if err != nil {
		logger.L().Warning("GetPod - k8s.podName field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return podName
}

func (e *DatasourceEvent) GetPodHostIP() string {
	hostIP, err := e.getFieldAccessor("k8s.hostIP").String(e.Data)
	if err != nil {
		logger.L().Warning("GetPodHostIP - k8s.hostIP field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	return hostIP
}

func (e *DatasourceEvent) GetPodLabels() map[string]string {
	podLabels, err := e.getFieldAccessor("k8s.podLabels").String(e.Data)
	if err != nil {
		logger.L().Warning("GetPodLabels - k8s.podLabels field not found in event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
	return parseStringToMap(podLabels)
}

func (e *DatasourceEvent) GetPpid() uint32 {
	switch e.EventType {
	case ForkEventType:
		parentPid, err := e.getFieldAccessor("parent_pid").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetPpid - parent_pid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		return parentPid
	case ExitEventType:
		exitPpid, err := e.getFieldAccessor("exit_ppid").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetPpid - exit_ppid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		return exitPpid
	default:
		ppid, err := e.getFieldAccessor("proc.parent.pid").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetPpid - proc.parent.pid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		return ppid
	}
}

func (e *DatasourceEvent) GetProto() string {
	switch e.EventType {
	case DnsEventType:
		protoNum, err := e.getFieldAccessor("dst.proto_raw").Uint16(e.Data)
		if err != nil {
			logger.L().Warning("GetProto - dst.proto_raw field not found in event type", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		return protoNumToString(protoNum)
	case NetworkEventType:
		protoNum, err := e.getFieldAccessor("endpoint.proto_raw").Uint16(e.Data)
		if err != nil {
			logger.L().Warning("GetProto - endpoint.proto_raw field not found in event type", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		return protoNumToString(protoNum)
	default:
		logger.L().Warning("GetProto not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetPupperLayer() bool {
	pupperLayer, err := e.getFieldAccessor("pupper_layer").Bool(e.Data)
	if err != nil {
		logger.L().Warning("GetPupperLayer - pupper_layer field not found in event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
	return pupperLayer
}

func (e *DatasourceEvent) GetQr() DNSPktType {
	isResponse, err := e.getFieldAccessor("qr_raw").Bool(e.Data)
	if err != nil {
		logger.L().Warning("GetQr - qr_raw field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
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
	signal, err := e.getFieldAccessor("exit_signal").Uint32(e.Data)
	if err != nil {
		logger.L().Warning("GetSignal - exit_signal field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return signal
}

func (e *DatasourceEvent) GetSocketInode() uint64 {
	socketInode, err := e.getFieldAccessor("socket_inode").Uint64(e.Data)
	if err != nil {
		logger.L().Warning("GetSocketInode - socket_inode field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return socketInode
}

func (e *DatasourceEvent) GetSockFd() uint32 {
	sockFd, err := e.getFieldAccessor("sock_fd").Uint32(e.Data)
	if err != nil {
		logger.L().Warning("GetSockFd - sock_fd field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return sockFd
}

func (e *DatasourceEvent) GetSrcIP() string {
	version, err := e.getFieldAccessor("src.version").Uint8(e.Data)
	if err != nil {
		logger.L().Warning("GetSrcIP - src.version field not found in event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
	switch version {
	case 4:
		addr, err := e.getFieldAccessor("src.addr_raw.v4").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetSrcIP - src.addr_raw.v4 field not found in event type", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		return rawIPv4ToString(addr)
	case 6:
		addr, err := e.getFieldAccessor("src.addr_raw.v6").Bytes(e.Data)
		if err != nil {
			logger.L().Warning("GetSrcIP - src.addr_raw.v6 field not found in event type", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		return rawIPv6ToString(addr)
	}
	return ""
}

func (e *DatasourceEvent) GetSrcPort() uint16 {
	port, err := e.getFieldAccessor("src.port").Uint16(e.Data)
	if err != nil {
		logger.L().Warning("GetSrcPort - src.port field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return port
}

func (e *DatasourceEvent) GetSyscall() string {
	switch e.EventType {
	case CapabilitiesEventType:
		syscallRaw, err := e.getFieldAccessor("syscall_raw").Uint16(e.Data)
		if err != nil {
			logger.L().Warning("GetSyscall - syscall_raw field not found in event type", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		return syscalls.SyscallGetName(syscallRaw)
	case HTTPEventType:
		syscall, err := e.getFieldAccessor("syscall").Bytes(e.Data)
		if err != nil {
			logger.L().Warning("GetSyscall - syscall field not found in event type", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		return gadgets.FromCString(syscall)
	case SyscallEventType:
		return e.Syscall
	case KmodEventType:
		syscall, err := e.getFieldAccessor("syscall").String(e.Data)
		if err != nil {
			logger.L().Warning("GetSyscall - syscall field not found in event type", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		return syscall
	default:
		logger.L().Warning("GetSyscall not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetSyscalls() []byte {
	syscallsBuffer, err := e.getFieldAccessor("syscalls").Bytes(e.Data)
	if err != nil {
		logger.L().Warning("GetSyscalls - syscalls field not found in event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
	return syscallsBuffer
}

func (e *DatasourceEvent) getTid() uint64 {
	switch e.EventType {
	case ExitEventType:
		tid, err := e.getFieldAccessor("exit_tid").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("getTid - exit_tid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		return uint64(tid)
	default:
		tid, err := e.getFieldAccessor("proc.tid").Uint32(e.Data)
		if err != nil {
			logger.L().Warning("getTid - proc.tid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		return uint64(tid)
	}
}

func (e *DatasourceEvent) GetTimestamp() types.Time {
	switch e.EventType {
	case SyscallEventType:
		return types.Time(time.Now().UnixNano())
	default:
		timeStampRaw, err := e.getFieldAccessor("timestamp_raw").Uint64(e.Data)
		if err != nil {
			logger.L().Warning("GetTimestamp - timestamp_raw field not found in event type", helpers.String("eventType", string(e.EventType)))
			return types.Time(0)
		}
		return gadgets.WallTimeFromBootTime(timeStampRaw)
	}
}

func (e *DatasourceEvent) GetType() HTTPDataType {
	t, err := e.getFieldAccessor("type").Uint8(e.Data)
	if err != nil {
		logger.L().Warning("GetType - type field not found in event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
	return HTTPDataType(t)
}

func (e *DatasourceEvent) GetUid() *uint32 {
	uid, err := e.getFieldAccessor("proc.creds.uid").Uint32(e.Data)
	if err != nil {
		logger.L().Warning("GetUid - proc.creds.uid field not found in event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
	return &uid
}

func (e *DatasourceEvent) GetUpperLayer() bool {
	upperLayer, err := e.getFieldAccessor("upper_layer").Bool(e.Data)
	if err != nil {
		logger.L().Warning("GetUpperLayer - upper_layer field not found in event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
	return upperLayer
}

func (e *DatasourceEvent) HasDroppedEvents() bool {
	if e.Data.LostSampleCount() > 0 {
		return true
	}
	return false
}

func (e *DatasourceEvent) IsDir() bool {
	raw, err := e.getFieldAccessor("mode_raw").Uint32(e.Data)
	if err != nil {
		logger.L().Warning("IsDir - mode_raw field not found in event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
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
