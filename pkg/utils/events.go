package utils

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
	RandomXEventType
	AllEventType
)
