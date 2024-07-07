package types

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID

	Pid        uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	PPid       uint32 `json:"ppid,omitempty" column:"ppid,template:ppid"`
	Uid        uint32 `json:"uid,omitempty" column:"uid,template:uid"`
	Gid        uint32 `json:"gid,omitempty" column:"gid,template:gid"`
	UpperLayer bool   `json:"upperlayer,omitempty" column:"upperlayer,template:upperlayer"`
	Comm       string `json:"comm,omitempty" column:"comm,template:comm"`
	ExePath    string `json:"exe_path,omitempty" column:"exe_path,template:exe_path"`
	MapName    string `json:"map_name,omitempty" column:"map_name,template:map_name"`
}

func GetColumns() *columns.Columns[Event] {
	antitamperingColumns := columns.MustCreateColumns[Event]()

	return antitamperingColumns
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}
