package utils

import (
	"os"
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

type DatasourceEvent struct {
	Data       datasource.Data
	Datasource datasource.DataSource
	EventType  EventType
	extra      interface{}
}

var _ EverythingEvent = (*DatasourceEvent)(nil)

func (e *DatasourceEvent) GetAddresses() []string {
	switch e.EventType {
	case DnsEventType:
		args, _ := e.Datasource.GetField("addresses").String(e.Data)
		return strings.Split(args, ",")
	default:
		return nil
	}
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

func (e *DatasourceEvent) GetBuf() []byte {
	switch e.EventType {
	case HTTPEventType:
		buf, _ := e.Datasource.GetField("buf").Bytes(e.Data)
		return buf
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
	switch e.EventType {
	case DnsEventType:
		dnsName, _ := e.Datasource.GetField("name").String(e.Data)
		return dnsName
	default:
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
		return types.L4Endpoint{}
	}
}

func (e *DatasourceEvent) GetDstIP() string {
	switch e.EventType {
	case SSHEventType:
		version, _ := e.Datasource.GetField("dst.version").Uint8(e.Data)
		if version == 4 {
			daddr, _ := e.Datasource.GetField("dst.addr_raw.v4").Uint32(e.Data)
			return rawIPv4ToString(daddr)
		} else if version == 6 {
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
	default:
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
	case ExecveEventType:
		exepath, _ := e.Datasource.GetField("exepath").String(e.Data)
		return exepath
	default:
		return ""
	}
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

func (e *DatasourceEvent) GetFlagsRaw() uint32 {
	switch e.EventType {
	case OpenEventType:
		flags, _ := e.Datasource.GetField("flags_raw").Int32(e.Data)
		return uint32(flags)
	default:
		return 0
	}
}

func (e *DatasourceEvent) GetGid() *uint32 {
	switch e.EventType {
	case ExecveEventType, ExitEventType, ForkEventType, HTTPEventType:
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

func (e *DatasourceEvent) GetHostNetwork() bool {
	hostNetwork, _ := e.Datasource.GetField("k8s.hostnetwork").Bool(e.Data)
	return hostNetwork
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
		return ""
	}
}

func (e *DatasourceEvent) GetNumAnswers() int {
	switch e.EventType {
	case DnsEventType:
		numAnswers, _ := e.Datasource.GetField("num_answers").Int32(e.Data)
		return int(numAnswers)
	default:
		return 0
	}
}

func (e *DatasourceEvent) GetOldPath() string {
	switch e.EventType {
	case HardlinkEventType, SymlinkEventType:
		oldPath, _ := e.Datasource.GetField("oldpath").String(e.Data)
		return oldPath
	default:
		return ""
	}
}

func (e *DatasourceEvent) GetOpcode() int {
	switch e.EventType {
	case IoUringEventType:
		opcode, _ := e.Datasource.GetField("opcode").Int32(e.Data)
		return int(opcode)
	default:
		return 0
	}
}

func (e *DatasourceEvent) GetPath() string {
	switch e.EventType {
	case OpenEventType:
		path, _ := e.Datasource.GetField("fname").String(e.Data)
		return path
	default:
		return ""
	}
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
		return ""
	}
}

func (e *DatasourceEvent) GetPodLabels() map[string]string {
	podLabels, _ := e.Datasource.GetField("k8s.podLabels").String(e.Data)
	return parseStringToMap(podLabels)
}

func (e *DatasourceEvent) GetPpid() uint32 {
	ppid, _ := e.Datasource.GetField("proc.parent.pid").Uint32(e.Data)
	return ppid
}

func (e *DatasourceEvent) GetProto() string {
	switch e.EventType {
	case NetworkEventType:
		// TODO fix proto raw to string mapping
		proto, _ := e.Datasource.GetField("endpoint.proto_raw").String(e.Data)
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
	switch e.EventType {
	case DnsEventType:
		isResponse, _ := e.Datasource.GetField("qr_raw").Bool(e.Data)
		if isResponse {
			return DNSPktTypeResponse
		}
		return DNSPktTypeQuery
	default:
		return ""
	}
}

func (e *DatasourceEvent) GetSocketInode() uint64 {
	switch e.EventType {
	case HTTPEventType:
		socketInode, _ := e.Datasource.GetField("socket_inode").Uint64(e.Data)
		return socketInode
	default:
		return 0
	}
}

func (e *DatasourceEvent) GetSockFd() uint32 {
	switch e.EventType {
	case HTTPEventType:
		sockFd, _ := e.Datasource.GetField("sock_fd").Uint32(e.Data)
		return sockFd
	default:
		return 0
	}
}

func (e *DatasourceEvent) GetSrcIP() string {
	switch e.EventType {
	case SSHEventType:
		version, _ := e.Datasource.GetField("src.version").Uint8(e.Data)
		if version == 4 {
			addr, _ := e.Datasource.GetField("src.addr_raw.v4").Uint32(e.Data)
			return rawIPv4ToString(addr)
		} else if version == 6 {
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

func (e *DatasourceEvent) GetType() HTTPDataType {
	switch e.EventType {
	case HTTPEventType:
		t, _ := e.Datasource.GetField("type").Uint8(e.Data)
		return HTTPDataType(t)
	default:
		return 0
	}
}

func (e *DatasourceEvent) GetUid() *uint32 {
	switch e.EventType {
	case ExecveEventType, ExitEventType, ForkEventType, HTTPEventType:
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
	switch e.EventType {
	case OpenEventType:
		raw, _ := e.Datasource.GetField("mode_raw").Uint32(e.Data)
		fileMode := os.FileMode(raw)
		return (fileMode & os.ModeType) == os.ModeDir // FIXME not sure if this is correct
	default:
		return false
	}
}

func (e *DatasourceEvent) SetExtra(extra interface{}) {
	e.extra = extra
}
