package ebpfev

import (
	"time"
)

type EventClient interface {
	GetEventTimestamp() time.Time
	GetEventContainerID() string
	GetEventPPID() string
	GetEventPID() string
	GetEventSyscallOp() string
	GetEventSyscallArgs() string
	GetEventEXE() string
	GetEventCMD() string
}
