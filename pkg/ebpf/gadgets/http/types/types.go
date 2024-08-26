package types

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type HTTPData interface {
}

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID
	eventtypes.WithNetNsID

	Pid       uint32   `json:"pid,omitempty" column:"pid,template:pid"`
	Uid       uint32   `json:"uid,omitempty" column:"uid,template:uid"`
	Gid       uint32   `json:"gid,omitempty" column:"gid,template:gid"`
	OtherPort uint16   `json:"other_port,omitempty" column:"other_port,template:other_port"`
	OtherIp   string   `json:"other_ip,omitempty" column:"other_ip,template:other_ip"`
	Syscall   string   `json:"syscall,omitempty" column:"syscall,template:syscall"`
	Headers   HTTPData `json:"headers,omitempty" column:"headers,template:headers"`
}

func GetColumns() *columns.Columns[Event] {
	sshColumns := columns.MustCreateColumns[Event]()

	return sshColumns
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}
