package ebpfev

import (
	"time"
)

type EventClient interface {
	GetEventTimestamp(ev EventData) time.Time
	GetEventContainerID(ev EventData) string
	GetEventPPID(ev EventData) string
	GetEventPID(ev EventData) string
	GetEventSyscallOp(ev EventData) string
	GetEventSyscallArgs(ev EventData) string
	GetEventEXE(ev EventData) string
	GetEventCMD(ev EventData) string
}
