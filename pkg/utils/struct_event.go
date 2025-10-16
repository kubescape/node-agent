package utils

import (
	"net/http"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/consts"
)

type StructEvent struct {
	Addresses            []string
	Args                 []string
	Buf                  []byte
	CapName              string
	Comm                 string
	Container            string
	ContainerID          string
	ContainerImage       string
	ContainerImageDigest string
	Cwd                  string
	DNSName              string
	Direction            consts.NetworkDirection
	DstEndpoint          eventtypes.L3Endpoint
	DstIP                string
	DstPort              uint16
	Error                int64
	EventType            EventType
	ExePath              string
	Extra                interface{}
	Flags                []string
	FlagsRaw             uint32
	FullPath             string
	Gid                  uint32
	HostNetwork          bool
	ID                   string
	Identifier           string
	Internal             bool
	Namespace            string
	NewPath              string
	OldPath              string
	Opcode               int
	Path                 string
	Pcomm                string
	Pid                  uint32
	PktType              string
	Pod                  string
	PodHostIP            string
	PodLabels            map[string]string
	Ppid                 uint32
	Proto                string
	PtraceRequest        int
	PupperLayer          bool
	Qr                   DNSPktType
	Request              *http.Request
	Response             *http.Response
	SockFd               uint32
	SocketInode          uint64
	SrcIP                string
	SrcPort              uint16
	StatusCode           int
	Syscall              string
	Timestamp            int64
	Type                 HTTPDataType
	Uid                  uint32
	UpperLayer           bool
	UserData             int
}

var _ EverythingEvent = (*StructEvent)(nil)
var _ HttpEvent = (*StructEvent)(nil)

func (e StructEvent) GetAddresses() []string {
	return e.Addresses
}

func (e StructEvent) GetArgs() []string {
	return e.Args
}

func (e StructEvent) GetBuf() []byte {
	return e.Buf
}

func (e StructEvent) GetCapability() string {
	return e.CapName
}

func (e StructEvent) GetComm() string {
	return e.Comm
}

func (e StructEvent) GetContainer() string {
	return e.Container
}

func (e StructEvent) GetContainerID() string {
	return e.ContainerID
}

func (e StructEvent) GetContainerImage() string {
	return e.ContainerImage
}

func (e StructEvent) GetContainerImageDigest() string {
	return e.ContainerImageDigest
}

func (e StructEvent) GetCwd() string {
	return e.Cwd
}

func (e StructEvent) GetDirection() consts.NetworkDirection {
	return e.Direction
}

func (e StructEvent) GetDNSName() string {
	return e.DNSName
}

func (e StructEvent) GetDstEndpoint() eventtypes.L4Endpoint {
	return eventtypes.L4Endpoint{
		L3Endpoint: e.DstEndpoint,
	}
}

func (e StructEvent) GetDstIP() string {
	return e.DstIP
}

func (e StructEvent) GetDstPort() uint16 {
	return e.DstPort
}

func (e StructEvent) GetError() int64 {
	return e.Error
}

func (e StructEvent) GetEventType() EventType {
	return e.EventType
}

func (e StructEvent) GetExePath() string {
	return e.ExePath
}

func (e StructEvent) GetExtra() interface{} {
	return e.Extra
}

func (e StructEvent) GetFlags() []string {
	return e.Flags
}

func (e StructEvent) GetFlagsRaw() uint32 {
	return e.FlagsRaw
}

func (e StructEvent) GetFullPath() string {
	return e.FullPath
}

func (e StructEvent) GetGid() *uint32 {
	return &e.Gid
}

func (e StructEvent) GetHostNetwork() bool {
	return e.HostNetwork
}

func (e StructEvent) GetInternal() bool {
	return e.Internal
}

func (e StructEvent) GetNamespace() string {
	return e.Namespace
}

func (e StructEvent) GetNewPath() string {
	return e.NewPath
}

func (e StructEvent) GetNumAnswers() int {
	return 0
}

func (e StructEvent) GetOldPath() string {
	return e.OldPath
}

func (e StructEvent) GetOpcode() int {
	return e.Opcode
}

func (e StructEvent) GetPath() string {
	return e.Path
}

func (e StructEvent) GetPcomm() string {
	return e.Pcomm
}

func (e StructEvent) GetPID() uint32 {
	return e.Pid
}

func (e StructEvent) GetPktType() string {
	return e.PktType
}

func (e StructEvent) GetPod() string {
	return e.Pod
}

func (e StructEvent) GetPodHostIP() string {
	return e.PodHostIP
}

func (e StructEvent) GetPodLabels() map[string]string {
	return e.PodLabels
}

func (e StructEvent) GetPpid() uint32 {
	return e.Ppid
}

func (e StructEvent) GetProto() string {
	return e.Proto
}

func (e StructEvent) GetPupperLayer() bool {
	return e.PupperLayer
}

func (e StructEvent) GetQr() DNSPktType {
	return e.Qr
}

func (e StructEvent) GetRequest() *http.Request {
	return e.Request
}

func (e StructEvent) GetResponse() *http.Response {
	return e.Response
}

func (e StructEvent) GetSocketInode() uint64 {
	return e.SocketInode
}

func (e StructEvent) GetSockFd() uint32 {
	return e.SockFd
}

func (e StructEvent) GetSrcIP() string {
	return e.SrcIP
}

func (e StructEvent) GetSrcPort() uint16 {
	return e.SrcPort
}

func (e StructEvent) GetSyscall() string {
	return e.Syscall
}

func (e StructEvent) GetSyscalls() []string {
	return []string{e.Syscall}
}

func (e StructEvent) GetTimestamp() eventtypes.Time {
	return eventtypes.Time(e.Timestamp)
}

func (e StructEvent) GetType() HTTPDataType {
	return e.Type
}

func (e StructEvent) GetUid() *uint32 {
	return &e.Uid
}

func (e StructEvent) GetUpperLayer() bool {
	return e.UpperLayer
}

func (e StructEvent) IsDir() bool {
	return false
}

func (e StructEvent) SetExtra(extra interface{}) {
	e.Extra = extra
}

func (e StructEvent) SetRequest(request *http.Request) {
	e.Request = request
}

func (e StructEvent) SetResponse(response *http.Response) {
	e.Response = response
}
