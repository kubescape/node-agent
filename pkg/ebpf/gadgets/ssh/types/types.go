package types

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID
	eventtypes.WithNetNsID

	Pid     uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Uid     uint32 `json:"uid,omitempty" column:"uid,template:uid"`
	Gid     uint32 `json:"gid,omitempty" column:"gid,template:gid"`
	Comm    string `json:"comm,omitempty" column:"comm,template:comm"`
	SrcPort uint16 `json:"src_port,omitempty" column:"src_port,template:src_port"`
	DstPort uint16 `json:"dst_port,omitempty" column:"dst_port,template:dst_port"`
	SrcIP   string `json:"src_ip,omitempty" column:"src_ip,template:src_ip"`
	DstIP   string `json:"dst_ip,omitempty" column:"dst_ip,template:dst_ip"`
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
