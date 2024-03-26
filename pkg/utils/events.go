package utils

import (
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
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
	ContainerID   string
}

func ExecToGeneralEvent(event *tracerexectype.Event) *GeneralEvent {

	return &GeneralEvent{
		ProcessDetails: ProcessDetails{
			Pid:  event.Pid,
			Ppid: event.Ppid,
			Comm: event.Comm,
			Cwd:  event.Cwd,
			Uid:  event.Uid,
			Gid:  event.Gid,
		},
		ContainerID:   event.GetBaseEvent().Runtime.ContainerID,
		ContainerName: event.GetContainer(),
		PodName:       event.GetPod(),
		Namespace:     event.GetNamespace(),
		MountNsID:     event.MountNsID,
		Timestamp:     int64(event.Timestamp),
		EventType:     ExecveEventType,
	}
}
func OpenToGeneralEvent(event *traceropentype.Event) *GeneralEvent {

	return &GeneralEvent{
		ProcessDetails: ProcessDetails{
			Pid:  event.Pid,
			Comm: event.Comm,
			Uid:  event.Uid,
			Gid:  event.Gid,
		},
		ContainerID:   event.GetBaseEvent().Runtime.ContainerID,
		ContainerName: event.GetContainer(),
		PodName:       event.GetPod(),
		Namespace:     event.GetNamespace(),
		MountNsID:     event.MountNsID,
		Timestamp:     int64(event.Timestamp),
		EventType:     OpenEventType,
	}
}

func CapabilitiesToGeneralEvent(event *tracercapabilitiestype.Event) *GeneralEvent {
	return &GeneralEvent{
		ProcessDetails: ProcessDetails{
			Pid:  event.Pid,
			Comm: event.Comm,
			Uid:  event.Uid,
			Gid:  event.Gid,
		},
		ContainerID:   event.GetBaseEvent().Runtime.ContainerID,
		ContainerName: event.GetContainer(),
		PodName:       event.GetPod(),
		Namespace:     event.GetNamespace(),
		MountNsID:     event.MountNsID,
		Timestamp:     int64(event.Timestamp),
		EventType:     CapabilitiesEventType,
	}
}

func DnsToGeneralEvent(event *tracerdnstype.Event) *GeneralEvent {
	return &GeneralEvent{
		ProcessDetails: ProcessDetails{
			Pid:  event.Pid,
			Comm: event.Comm,
			Uid:  event.Uid,
			Gid:  event.Gid,
		},
		ContainerID:   event.GetBaseEvent().Runtime.ContainerID,
		ContainerName: event.GetContainer(),
		PodName:       event.GetPod(),
		Namespace:     event.GetNamespace(),
		MountNsID:     event.MountNsID,
		Timestamp:     int64(event.Timestamp),
		EventType:     DnsEventType,
	}
}
func NetworkToGeneralEvent(event *tracernetworktype.Event) *GeneralEvent {
	return &GeneralEvent{
		ProcessDetails: ProcessDetails{
			Pid:  event.Pid,
			Comm: event.Comm,
			Uid:  event.Uid,
			Gid:  event.Gid,
		},
		ContainerID:   event.GetBaseEvent().Runtime.ContainerID,
		ContainerName: event.GetContainer(),
		PodName:       event.GetPod(),
		Namespace:     event.GetNamespace(),
		MountNsID:     event.MountNsID,
		Timestamp:     int64(event.Timestamp),
		EventType:     NetworkEventType,
	}
}
