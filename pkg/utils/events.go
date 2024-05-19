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
	SignalEventType
	AllEventType
)

type ProcessDetails struct {
	Pid  uint32
	Ppid uint32
	Comm string
	Cwd  string
	Uid  uint32
	Gid  uint32
}

type GeneralEvent struct {
	ProcessDetails
	ContainerName string
	Namespace     string
	PodName       string
	MountNsID     uint64
	Timestamp     int64
	EventType     EventType
	ContainerID   string
}
