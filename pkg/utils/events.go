package utils

type EventType int

const (
	ExecveEventType EventType = iota
	OpenEventType
	CapabilitiesEventType
	DnsEventType
	NetworkEventType
	SyscallEventType
	RandomXEventType
	SymlinkEventType
	HardlinkEventType
	AntitamperingEventType
	AllEventType
)
