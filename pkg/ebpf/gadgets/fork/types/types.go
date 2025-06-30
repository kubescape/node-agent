package types

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID

	Pid        uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Tid        uint32 `json:"tid,omitempty" column:"tid,template:tid"`
	PPid       uint32 `json:"ppid,omitempty" column:"ppid,template:ppid"`
	Uid        uint32 `json:"uid,omitempty" column:"uid,template:uid"`
	Gid        uint32 `json:"gid,omitempty" column:"gid,template:gid"`
	UpperLayer bool   `json:"upperlayer,omitempty" column:"upperlayer,template:upperlayer"`
	Comm       string `json:"comm,omitempty" column:"comm,template:comm"`
	ExePath    string `json:"exe_path,omitempty" column:"exe_path,template:exe_path"`
	ChildPid   uint32 `json:"child_pid,omitempty" column:"child_pid,template:child_pid"`
	ChildTid   uint32 `json:"child_tid,omitempty" column:"child_tid,template:child_tid"`
	extra      interface{}
}

func (event *Event) SetExtra(extra interface{}) {
	event.extra = extra
}

func (event *Event) GetExtra() interface{} {
	return event.extra
}

func (event *Event) GetPID() uint64 {
	return (uint64(event.Pid) << 32) | uint64(event.Tid)
}

func GetColumns() *columns.Columns[Event] {
	forkColumns := columns.MustCreateColumns[Event]()

	return forkColumns
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}
