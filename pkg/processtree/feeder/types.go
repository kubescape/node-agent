package feeder

import (
	"time"
)

type ProcessEventType int

const (
	ForkEvent ProcessEventType = iota
	ExecEvent
	ExitEvent
	ProcfsEvent
)

type ProcessEvent struct {
	Type      ProcessEventType
	Timestamp time.Time

	// Process identity
	PID         uint32
	PPID        uint32
	Comm        string
	Pcomm       string
	Cmdline     string
	Uid         *uint32
	Gid         *uint32
	Cwd         string
	Path        string
	StartTimeNs uint64 // Process start time in nanoseconds for unique identification

	// Container context
	ContainerID string

	// Host context
	HostPID  int
	HostPPID int
}
