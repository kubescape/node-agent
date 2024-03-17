package utils

import (
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

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
	// ContainerID   string
}

func ExecToGeneralEvent(exec *tracerexectype.Event) *GeneralEvent {
	return &GeneralEvent{
		ProcessDetails: ProcessDetails{
			Pid:  exec.Pid,
			Ppid: exec.Ppid,
			Comm: exec.Comm,
			Cwd:  exec.Cwd,
			Uid:  exec.Uid,
			Gid:  exec.Gid,
		},
		ContainerName: exec.GetContainer(),
		PodName:       exec.GetPod(),
		Namespace:     exec.GetNamespace(),
		MountNsID:     exec.MountNsID,
		Timestamp:     int64(exec.Timestamp),
		EventType:     ExecveEventType,
	}
}
