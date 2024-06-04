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
	OldPath    string `json:"oldpath,omitempty" column:"oldpath,template:oldpath"`
	NewPath    string `json:"newpath,omitempty" column:"newpath,template:newpath"`
}

func GetColumns() *columns.Columns[Event] {
	symlinkColumns := columns.MustCreateColumns[Event]()

	return symlinkColumns
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}
