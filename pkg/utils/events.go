package utils

import (
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

type HTTPDataType int

const (
	HostPktType                  = "HOST"
	OutgoingPktType              = "OUTGOING"
	Request         HTTPDataType = 2
	Response        HTTPDataType = 3
)

type K8sEvent interface {
	GetContainerID() string
	GetEventType() EventType
	GetNamespace() string
	GetPod() string
	GetTimestamp() types.Time
	HasDroppedEvents() bool
	Release()
}

type EnrichEvent interface {
	K8sEvent
	GetComm() string
	GetContainer() string
	GetContainerImage() string
	GetContainerImageDigest() string
	GetError() int64
	GetExtra() any
	FieldPresent(name string) bool
	GetGid() *uint32
	GetHostNetwork() bool
	GetMountNsID() uint64
	GetPcomm() string
	GetPID() uint32
	GetPID64() uint64
	GetPodLabels() map[string]string
	GetPpid() uint32
	GetUid() *uint32
	SetExtra(extra any)

	// ECS-specific methods
	GetEcsClusterName() string
	GetEcsClusterARN() string
	GetEcsTaskARN() string
	GetEcsTaskFamily() string
	GetEcsTaskDefinitionARN() string
	GetEcsServiceName() string
	GetEcsContainerName() string
	GetEcsContainerARN() string
	GetEcsContainerInstance() string
	GetEcsAvailabilityZone() string
	GetEcsLaunchType() string
}

type BpfEvent interface {
	EnrichEvent
	GetExePath() string
	GetCmd() uint32
	GetAttrSize() uint32
	GetUpperLayer() bool
}

type CapabilitiesEvent interface {
	EnrichEvent
	GetCapability() string
	GetSyscall() string
}

type DNSEvent interface {
	EnrichEvent
	GetAddresses() []string
	GetCwd() string
	GetDNSName() string
	GetDstIP() string
	GetDstPort() uint16
	GetExePath() string
	GetNumAnswers() int
	GetProto() string
	GetQr() DNSPktType
	// GetQtype returns the question type as the gadget names it ("A", "AAAA",
	// "TXT", ...), or the decimal type number for types without a name.
	GetQtype() string
	// GetRcode returns the response code name ("Success", "NameError",
	// "ServerFailure", "Refused", ...) for a response, and "" for a query.
	GetRcode() string
	GetSrcIP() string
	GetSrcPort() uint16
}

// RuleOnlyEvent is implemented by events that must reach the rule manager
// only, bypassing every other consumer of their event type (profile learning,
// DNS cache, network stream, metrics, third-party receivers). The DNS tracer
// marks forwarded queries and error responses this way: they carry no answer
// addresses and would otherwise trigger agent-side lookups in the DNS manager
// and be recorded as outbound connections by the network stream.
type RuleOnlyEvent interface {
	IsRuleOnly() bool
}

// IsRuleOnlyEvent reports whether e is marked rule-only.
func IsRuleOnlyEvent(e K8sEvent) bool {
	if ro, ok := e.(RuleOnlyEvent); ok {
		return ro.IsRuleOnly()
	}
	return false
}

// RuleEventType returns the event type the rule manager uses to select rule
// expressions for e. For a rule-only DNS event this is DnsQueryRuleEventType,
// so that rules opt in with `eventType: "dnsQuery"` and existing "dns"
// expressions keep matching answered responses only. For every other event it
// is the event's own type.
func RuleEventType(e K8sEvent) EventType {
	t := e.GetEventType()
	if t == DnsEventType && IsRuleOnlyEvent(e) {
		return DnsQueryRuleEventType
	}
	return t
}

type ExecEvent interface {
	EnrichEvent
	GetArgs() []string
	GetCwd() string
	GetExePath() string
	GetFile() string
	GetHasTTY() bool
	GetParentExePath() string
	GetPupperLayer() bool
	GetTTY() int32
	GetTTYMajor() uint32
	GetTTYMinor() uint32
	GetUpperLayer() bool
}

type ExitEvent interface {
	EnrichEvent
	GetExitCode() uint32
	GetSignal() uint32
}

type ForkEvent interface {
	EnrichEvent
	GetExePath() string
}

type HttpEvent interface {
	HttpRawEvent
	GetDirection() consts.NetworkDirection
	GetInternal() bool
	GetOtherIp() string
	GetRequest() *http.Request
	GetResponse() *http.Response
	SetResponse(response *http.Response)
}

type HttpRawEvent interface {
	EnrichEvent
	GetBuf() []byte
	GetBufLen() uint16
	GetDstIP() string
	GetDstPort() uint16
	GetSockFd() uint32
	GetSocketInode() uint64
	GetSrcIP() string
	GetSrcPort() uint16
	GetSyscall() string
	GetType() HTTPDataType
	MakeHttpEvent(request *http.Request, direction consts.NetworkDirection) HttpEvent
}

type IOUring interface {
	EnrichEvent
	GetFlags() []string
	GetIdentifier() string
	GetOpcode() int
}

type KmodEvent interface {
	EnrichEvent
	GetModule() string
	GetExePath() string
	GetSyscall() string
	GetUpperLayer() bool
}

type LinkEvent interface {
	EnrichEvent
	GetExePath() string
	GetNewPath() string
	GetOldPath() string
	GetUpperLayer() bool
}

type NetworkEvent interface {
	EnrichEvent
	GetExePath() string
	GetDstEndpoint() types.L4Endpoint
	GetDstPort() uint16
	GetPktType() string
	GetPodHostIP() string
	GetProto() string
}

type OpenEvent interface {
	EnrichEvent
	GetFlags() []string
	GetFlagsRaw() uint32
	GetFullPath() string
	GetPath() string
	IsDir() bool
}

type PtraceEvent interface {
	EnrichEvent
	GetExePath() string
}

type SshEvent interface {
	EnrichEvent
	GetDstIP() string
	GetDstPort() uint16
	GetSrcIP() string
	GetSrcPort() uint16
}

type SyscallEvent interface {
	EnrichEvent
	GetSyscall() string
}

type UnshareEvent interface {
	EnrichEvent
	GetExePath() string
	// GetFlags() uint64
	GetUpperLayer() bool
}

type EventType string

const (
	AllEventType          EventType = "all"
	BpfEventType          EventType = "bpf"
	CapabilitiesEventType EventType = "capabilities"
	DnsEventType          EventType = "dns"
	// DnsQueryRuleEventType is not a tracer event type. It is the rule-selection
	// alias for DNS queries and error responses forwarded to the rule manager
	// (see RuleEventType); such events still report DnsEventType from
	// GetEventType so every DNS accessor and adapter applies to them.
	DnsQueryRuleEventType EventType = "dnsQuery"
	ExecveEventType       EventType = "exec"
	ExitEventType         EventType = "exit"
	ForkEventType         EventType = "fork"
	HTTPEventType         EventType = "http"
	HardlinkEventType     EventType = "hardlink"
	IoUringEventType      EventType = "iouring"
	KmodEventType         EventType = "kmod"
	NetworkEventType      EventType = "network"
	OpenEventType         EventType = "open"
	ProcfsEventType       EventType = "procfs"
	PtraceEventType       EventType = "ptrace"
	RandomXEventType      EventType = "randomx"
	SSHEventType          EventType = "ssh"
	SymlinkEventType      EventType = "symlink"
	SyscallEventType      EventType = "syscall"
	UnshareEventType      EventType = "unshare"
)

// GetHostFilePathFromEvent returns the primary host path of the file behind
// the event. For an exec event this is the first path from
// GetHostFilePathsFromEvent. Use GetHostFilePathsFromEvent to also get the
// interpreter path of a script or a binfmt_misc binary.
func GetHostFilePathFromEvent(event EnrichEvent, containerPid uint32) (string, error) {
	paths, err := GetHostFilePathsFromEvent(event, containerPid)
	if err != nil {
		return "", err
	}
	if len(paths) == 0 {
		return "", fmt.Errorf("no scannable path for event")
	}
	return paths[0], nil
}

// GetHostFilePathsFromEvent returns the host paths of the files behind the
// event.
//
// An open event yields its full path under the container root.
//
// An exec event yields the executed file (`file`) under the container root. If
// `file` is empty, a memfd ("/memfd:...") or a deleted file ("... (deleted)"),
// the kernel no longer has a reachable path, so /proc/<pid>/exe is used, or the
// path is skipped when the pid is unknown. If `exepath` differs from `file`
// (a shebang script or a binfmt_misc binary), the interpreter is returned too.
func GetHostFilePathsFromEvent(event EnrichEvent, containerPid uint32) ([]string, error) {
	switch event.GetEventType() {
	case ExecveEventType:
		return getExecHostFilePaths(event.(ExecEvent), containerPid), nil
	case OpenEventType:
		return []string{containerRootPath(containerPid, event.(OpenEvent).GetFullPath())}, nil
	default:
		return nil, fmt.Errorf("event is not of type exec or open")
	}
}

func getExecHostFilePaths(event ExecEvent, containerPid uint32) []string {
	var paths []string
	add := func(p string) {
		if p != "" && !slices.Contains(paths, p) {
			paths = append(paths, p)
		}
	}
	resolve := func(p string) string {
		if !isUnreachableExecPath(p) {
			return containerRootPath(containerPid, p)
		}
		if pid := event.GetPID(); pid != 0 {
			return filepath.Join("/proc", fmt.Sprintf("%d", pid), "exe")
		}
		logger.L().Debug("GetHostFilePathsFromEvent - skipping exec path, pid unknown",
			helpers.String("path", p), helpers.String("containerID", event.GetContainerID()))
		return ""
	}

	file := event.GetFile()
	add(resolve(file))
	if exepath := event.GetExePath(); file != "" && exepath != "" && exepath != file {
		add(resolve(exepath))
	}
	return paths
}

// isUnreachableExecPath reports whether an exec path cannot be opened under
// the container root: it is empty, a memfd, or a deleted file.
func isUnreachableExecPath(p string) bool {
	return p == "" || strings.HasPrefix(p, "/memfd:") || strings.HasSuffix(p, " (deleted)")
}

func containerRootPath(containerPid uint32, p string) string {
	return filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, p))
}

// GetExecPathFromEvent returns the path of the executable: the resolved file
// (`file`), then the kernel exe path (`exepath`), then comm. argv[0] is never
// used: it is caller-controlled and, since IG v0.57, it is the real argv[0]
// ("sh"), not the requested pathname.
func GetExecPathFromEvent(event ExecEvent) string {
	if file := event.GetFile(); file != "" {
		return file
	}
	if exepath := event.GetExePath(); exepath != "" {
		return exepath
	}
	return event.GetComm()
}

// Get exec args from the given event.
func GetExecArgsFromEvent(event ExecEvent) []string {
	if args := event.GetArgs(); len(args) > 1 {
		return args[1:]
	}
	return []string{}
}

// protoNumToString converts a protocol number to its string representation
func protoNumToString(protoNum uint16) string {
	switch protoNum {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return ""
	}
}

// DirectionFromPktType maps an Inspektor Gadget packet type string to a NetworkDirection
func DirectionFromPktType(pktType string) consts.NetworkDirection {
	if strings.EqualFold(pktType, OutgoingPktType) {
		return consts.Outbound
	}
	return consts.Inbound
}
