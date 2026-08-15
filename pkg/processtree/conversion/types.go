package conversion

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
	// StartTimeWall is the process creation time as wall-clock time, derived by
	// the procfs feeder from /proc/stat btime + StartTimeNs. DISPLAY ONLY: btime
	// has whole-second resolution, so this value carries up to 1s of skew and
	// must never be compared for process identity — StartTimeNs is the sole
	// identity source. Zero for every event type except ProcfsEvent.
	StartTimeWall time.Time

	// Container context
	ContainerID    string
	ContainerMntNs uint64
	ContainerNetNs uint64

	// Host context
	HostPID  int
	HostPPID int
}
