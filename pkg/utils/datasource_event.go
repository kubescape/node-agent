package utils

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
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

type DatasourceEvent struct {
	Data       datasource.Data
	Datasource datasource.DataSource
	Direction  consts.NetworkDirection
	EventType  EventType
	extra      interface{}
	Internal   bool
	Request    *http.Request
	Response   *http.Response
	Syscall    string
}

var _ BpfEvent = (*DatasourceEvent)(nil)
var _ DNSEvent = (*DatasourceEvent)(nil)
var _ ExecEvent = (*DatasourceEvent)(nil)
var _ ExitEvent = (*DatasourceEvent)(nil)
var _ HttpEvent = (*DatasourceEvent)(nil)
var _ HttpRawEvent = (*DatasourceEvent)(nil)
var _ IOUring = (*DatasourceEvent)(nil)
var _ KmodEvent = (*DatasourceEvent)(nil)
var _ LinkEvent = (*DatasourceEvent)(nil)
var _ NetworkEvent = (*DatasourceEvent)(nil)
var _ OpenEvent = (*DatasourceEvent)(nil)
var _ SshEvent = (*DatasourceEvent)(nil)
var _ SyscallEvent = (*DatasourceEvent)(nil)

func (e *DatasourceEvent) GetAttrSize() uint32 {
	switch e.EventType {
	case BpfEventType:
		attrSize, _ := e.Datasource.GetField("attr_size").Uint32(e.Data)
		return attrSize
	default:
		logger.L().Warning("GetAttrSize not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetAddresses() []string {
	switch e.EventType {
	case DnsEventType:
		args, _ := e.Datasource.GetField("addresses").String(e.Data)
		return strings.Split(args, ",")
	default:
		logger.L().Warning("GetAddresses not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *DatasourceEvent) GetArgs() []string {
	switch e.EventType {
	case ExecveEventType:
		args, _ := e.Datasource.GetField("args").String(e.Data)
		return strings.Split(args, " ")
	default:
		logger.L().Warning("GetArgs not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *DatasourceEvent) GetBuf() []byte {
	switch e.EventType {
	case HTTPEventType:
		buf, _ := e.Datasource.GetField("buf").Bytes(e.Data)
		return buf
	default:
		logger.L().Warning("GetBuf not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *DatasourceEvent) GetCapability() string {
	switch e.EventType {
	case CapabilitiesEventType:
		capability, _ := e.Datasource.GetField("cap").String(e.Data)
		return capability
	default:
		logger.L().Warning("GetCapability not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetCmd() uint32 {
	switch e.EventType {
	case BpfEventType:
		cmd, _ := e.Datasource.GetField("cmd").Uint32(e.Data)
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
	default:
		comm := e.Datasource.GetField("proc.comm")
		if comm == nil {
			logger.L().Warning("GetComm - proc.comm field not found in event type", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		commValue, err := comm.String(e.Data)
		if err != nil {
			logger.L().Warning("GetComm - cannot read proc.comm field in event", helpers.String("eventType", string(e.EventType)))
			return ""
		}
		return commValue
	}
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
	case ExecveEventType, DnsEventType:
		cwd, _ := e.Datasource.GetField("cwd").String(e.Data)
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
		dnsName, _ := e.Datasource.GetField("name").String(e.Data)
		return dnsName
	default:
		logger.L().Warning("GetDNSName not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetDstEndpoint() types.L4Endpoint {
	switch e.EventType {
	case NetworkEventType:
		addr, _ := e.Datasource.GetField("endpoint.addr_raw.v4").Uint32(e.Data)
		kind, _ := e.Datasource.GetField("endpoint.k8s.kind").String(e.Data)
		name, _ := e.Datasource.GetField("endpoint.k8s.name").String(e.Data)
		namespace, _ := e.Datasource.GetField("endpoint.k8s.namespace").String(e.Data)
		podLabels, _ := e.Datasource.GetField("endpoint.k8s.labels").String(e.Data)
		version, _ := e.Datasource.GetField("endpoint.version").Uint8(e.Data)
		port, _ := e.Datasource.GetField("endpoint.port").Uint16(e.Data)
		proto, _ := e.Datasource.GetField("endpoint.proto_raw").Uint16(e.Data)
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
	case SSHEventType:
		version, _ := e.Datasource.GetField("dst.version").Uint8(e.Data)
		switch version {
		case 4:
			daddr, _ := e.Datasource.GetField("dst.addr_raw.v4").Uint32(e.Data)
			return rawIPv4ToString(daddr)
		case 6:
			daddr, _ := e.Datasource.GetField("dst.addr_raw.v6").Bytes(e.Data)
			return rawIPv6ToString(daddr)
		}
	}
	return ""
}

func (e *DatasourceEvent) GetDstPort() uint16 {
	switch e.EventType {
	case NetworkEventType:
		port, _ := e.Datasource.GetField("endpoint.port").Uint16(e.Data)
		return port
	case SSHEventType, DnsEventType:
		port, _ := e.Datasource.GetField("dst.port").Uint16(e.Data)
		return port
	default:
		logger.L().Warning("GetDstPort not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetError() int64 {
	err, _ := e.Datasource.GetField("error_raw").Int64(e.Data)
	return err
}

func (e *DatasourceEvent) GetEventType() EventType {
	return e.EventType
}

func (e *DatasourceEvent) GetExePath() string {
	switch e.EventType {
	case DnsEventType, ExecveEventType, ForkEventType, PtraceEventType, RandomXEventType, KmodEventType, UnshareEventType, BpfEventType:
		exepath, _ := e.Datasource.GetField("exepath").String(e.Data)
		return exepath
	default:
		logger.L().Warning("GetExePath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetExitCode() uint32 {
	switch e.EventType {
	case ExitEventType:
		exitCode, _ := e.Datasource.GetField("exit_code").Uint32(e.Data)
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
		flags, _ := e.Datasource.GetField("flags_raw").Int32(e.Data)
		return decodeOpenFlags(flags)
	default:
		logger.L().Warning("GetFlags not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return nil
	}
}

func (e *DatasourceEvent) GetFlagsRaw() uint32 {
	switch e.EventType {
	case OpenEventType:
		flags, _ := e.Datasource.GetField("flags_raw").Int32(e.Data)
		return uint32(flags)
	default:
		logger.L().Warning("GetFlagsRaw not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetGid() *uint32 {
	switch e.EventType {
	case CapabilitiesEventType, DnsEventType, ExecveEventType, ExitEventType, ForkEventType, HTTPEventType, NetworkEventType, OpenEventType, KmodEventType, UnshareEventType, BpfEventType:
		gid, err := e.Datasource.GetField("proc.creds.gid").Uint32(e.Data)
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
	hostNetwork, _ := e.Datasource.GetField("k8s.hostnetwork").Bool(e.Data)
	return hostNetwork
}

func (e *DatasourceEvent) GetIdentifier() string {
	switch e.EventType {
	case IoUringEventType:
		identifier, _ := e.Datasource.GetField("identifier").String(e.Data)
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
		module, _ := e.Datasource.GetField("module").String(e.Data)
		return module
	default:
		logger.L().Warning("GetModule not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetNamespace() string {
	namespace, _ := e.Datasource.GetField("k8s.namespace").String(e.Data)
	return namespace
}

func (e *DatasourceEvent) GetNewPath() string {
	switch e.EventType {
	case HardlinkEventType, SymlinkEventType:
		newPath, _ := e.Datasource.GetField("newpath").String(e.Data)
		return newPath
	default:
		logger.L().Warning("GetNewPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetNumAnswers() int {
	switch e.EventType {
	case DnsEventType:
		numAnswers, _ := e.Datasource.GetField("num_answers").Int32(e.Data)
		return int(numAnswers)
	default:
		logger.L().Warning("GetNumAnswers not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetOldPath() string {
	switch e.EventType {
	case HardlinkEventType, SymlinkEventType:
		oldPath, _ := e.Datasource.GetField("oldpath").String(e.Data)
		return oldPath
	default:
		logger.L().Warning("GetOldPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetOpcode() int {
	switch e.EventType {
	case IoUringEventType:
		opcode, _ := e.Datasource.GetField("opcode").Int32(e.Data)
		return int(opcode)
	default:
		logger.L().Warning("GetOpcode not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetPath() string {
	switch e.EventType {
	case OpenEventType:
		path, _ := e.Datasource.GetField("fname").String(e.Data)
		return path
	default:
		logger.L().Warning("GetPath not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetPcomm() string {
	pcomm, _ := e.Datasource.GetField("proc.parent.comm").String(e.Data)
	return pcomm
}

func (e *DatasourceEvent) GetPID() uint32 {
	switch e.EventType {
	case ForkEventType:
		childPid, _ := e.Datasource.GetField("child_pid").Uint32(e.Data)
		return childPid
	case ExitEventType:
		exitPid, _ := e.Datasource.GetField("exit_pid").Uint32(e.Data) // FIXME it's fine to use the proc enrichment here
		return exitPid
	case SyscallEventType:
		// FIXME this is a temporary workaround until the gadget has proc enrichment
		containerPid, _ := e.Datasource.GetField("runtime.containerPid").Uint32(e.Data)
		return containerPid
	default:
		pid := e.Datasource.GetField("proc.pid")
		if pid == nil {
			logger.L().Warning("GetPID - proc.pid field not found in event type", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		pidValue, err := pid.Uint32(e.Data)
		if err != nil {
			logger.L().Warning("GetPID cannot read proc.pid field in event", helpers.String("eventType", string(e.EventType)))
			return 0
		}
		return pidValue
	}
}

func (e *DatasourceEvent) GetPktType() string {
	egress, _ := e.Datasource.GetField("egress").Uint8(e.Data)
	if egress == 1 {
		return OutgoingPktType
	}
	return HostPktType
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
		logger.L().Warning("GetPodHostIP not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetPodLabels() map[string]string {
	podLabels, _ := e.Datasource.GetField("k8s.podLabels").String(e.Data)
	return parseStringToMap(podLabels)
}

func (e *DatasourceEvent) GetPpid() uint32 {
	switch e.EventType {
	case ForkEventType:
		parentPid, _ := e.Datasource.GetField("parent_pid").Uint32(e.Data)
		return parentPid
	case ExitEventType:
		exitPpid, _ := e.Datasource.GetField("exit_ppid").Uint32(e.Data) // FIXME it's fine to use the proc enrichment here
		return exitPpid
	default:
		ppid, _ := e.Datasource.GetField("proc.parent.pid").Uint32(e.Data)
		return ppid
	}
}

func (e *DatasourceEvent) GetProto() string {
	switch e.EventType {
	case DnsEventType:
		protoNum, _ := e.Datasource.GetField("dst.proto_raw").Uint16(e.Data)
		return protoNumToString(protoNum)
	case NetworkEventType:
		protoNum, _ := e.Datasource.GetField("endpoint.proto_raw").Uint16(e.Data)
		return protoNumToString(protoNum)
	default:
		logger.L().Warning("GetProto not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
	}
}

func (e *DatasourceEvent) GetPupperLayer() bool {
	switch e.EventType {
	case ExecveEventType:
		pupperLayer, _ := e.Datasource.GetField("pupper_layer").Bool(e.Data)
		return pupperLayer
	default:
		logger.L().Warning("GetPupperLayer not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
}

func (e *DatasourceEvent) GetQr() DNSPktType {
	switch e.EventType {
	case DnsEventType:
		isResponse, _ := e.Datasource.GetField("qr_raw").Bool(e.Data)
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
		signal, _ := e.Datasource.GetField("exit_signal").Uint32(e.Data)
		return signal
	default:
		logger.L().Warning("GetSignal not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetSocketInode() uint64 {
	switch e.EventType {
	case HTTPEventType:
		socketInode, _ := e.Datasource.GetField("socket_inode").Uint64(e.Data)
		return socketInode
	default:
		logger.L().Warning("GetSocketInode not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetSockFd() uint32 {
	switch e.EventType {
	case HTTPEventType:
		sockFd, _ := e.Datasource.GetField("sock_fd").Uint32(e.Data)
		return sockFd
	default:
		logger.L().Warning("GetSockFd not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetSrcIP() string {
	switch e.EventType {
	case SSHEventType:
		version, _ := e.Datasource.GetField("src.version").Uint8(e.Data)
		switch version {
		case 4:
			addr, _ := e.Datasource.GetField("src.addr_raw.v4").Uint32(e.Data)
			return rawIPv4ToString(addr)
		case 6:
			addr, _ := e.Datasource.GetField("src.addr_raw.v6").Bytes(e.Data)
			return rawIPv6ToString(addr)
		}
	}
	return ""
}

func (e *DatasourceEvent) GetSrcPort() uint16 {
	switch e.EventType {
	case SSHEventType:
		port, _ := e.Datasource.GetField("src.port").Uint16(e.Data)
		return port
	default:
		logger.L().Warning("GetSrcPort not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetSyscall() string {
	switch e.EventType {
	case CapabilitiesEventType:
		syscallRaw, _ := e.Datasource.GetField("syscall_raw").Uint16(e.Data)
		return syscalls.SyscallGetName(syscallRaw)
	case HTTPEventType:
		syscall, _ := e.Datasource.GetField("syscall").Bytes(e.Data)
		return gadgets.FromCString(syscall)
	case SyscallEventType:
		return e.Syscall
	case KmodEventType:
		syscall, _ := e.Datasource.GetField("syscall").String(e.Data)
		return syscall
	default:
		logger.L().Warning("GetSyscall not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return ""
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

func (e *DatasourceEvent) GetType() HTTPDataType {
	switch e.EventType {
	case HTTPEventType:
		t, _ := e.Datasource.GetField("type").Uint8(e.Data)
		return HTTPDataType(t)
	default:
		logger.L().Warning("GetEventType not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return 0
	}
}

func (e *DatasourceEvent) GetUid() *uint32 {
	switch e.EventType {
	case CapabilitiesEventType, DnsEventType, ExecveEventType, ExitEventType, ForkEventType, HTTPEventType, NetworkEventType, OpenEventType, KmodEventType, UnshareEventType, BpfEventType:
		uid, err := e.Datasource.GetField("proc.creds.uid").Uint32(e.Data)
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
		upperLayer, _ := e.Datasource.GetField("upper_layer").Bool(e.Data)
		return upperLayer
	default:
		logger.L().Warning("GetUpperLayer not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
}

func (e *DatasourceEvent) IsDir() bool {
	switch e.EventType {
	case OpenEventType:
		raw, _ := e.Datasource.GetField("mode_raw").Uint32(e.Data)
		fileMode := os.FileMode(raw)
		return (fileMode & os.ModeType) == os.ModeDir // FIXME not sure if this is correct
	default:
		logger.L().Warning("IsDir not implemented for event type", helpers.String("eventType", string(e.EventType)))
		return false
	}
}

func (e *DatasourceEvent) MakeHttpEvent(request *http.Request, direction consts.NetworkDirection, internal bool) HttpEvent {
	return &DatasourceEvent{
		Data:       e.Data,
		Datasource: e.Datasource,
		Direction:  direction,
		EventType:  e.EventType,
		Internal:   internal,
		Request:    request,
	}
}

func (e *DatasourceEvent) SetExtra(extra interface{}) {
	e.extra = extra
}

func (e *DatasourceEvent) SetResponse(response *http.Response) {
	e.Response = response
}
