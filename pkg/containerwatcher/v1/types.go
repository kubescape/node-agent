package containerwatcher

import "github.com/cilium/ebpf"

type GadgetTracerCommon interface {
	Stop()
}

type AttachableTracer interface {
	Attach(pid uint32) error
	Detach(pid uint32) error
	Close()
}

type PeekableTracer interface {
	Peek(nsMountId uint64) ([]string, error)
	Close()
}

type TracingState struct {
	usageReferenceCount    map[uint64]int
	eBpfContainerFilterMap *ebpf.Map
	gadget                 GadgetTracerCommon
	attachable             AttachableTracer
	peekable               PeekableTracer
}

const (
	ContainerActivityEventStart    = "start"
	ContainerActivityEventAttached = "attached"
	ContainerActivityEventStop     = "stop"
)

type EventType int

const (
	ExecveEventType EventType = iota
	OpenEventType
	CapabilitiesEventType
	DnsEventType
	NetworkEventType
	SyscallEventType
	AllEventType
)
