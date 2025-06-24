package feeder

import (
	"context"
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
	PID     uint32
	PPID    uint32
	Comm    string
	Pcomm   string
	Cmdline string
	Uid     *uint32
	Gid     *uint32
	Cwd     string
	Path    string

	// Container context
	ContainerID string

	// Host context
	HostPID  int
	HostPPID int

	// Extra fields for advanced correlation (optional)
	ProcessEntityId uint32 // unique process hash/entity id
	ParentEntityId  uint32 // unique parent process hash/entity id
}

type ProcessEventFeeder interface {
	Start(ctx context.Context) error
	Stop() error
	Subscribe(chan<- ProcessEvent)
}
