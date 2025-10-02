package types

import eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID
	Pid     uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	PPid    uint32 `json:"ppid,omitempty" column:"ppid,template:ppid"`
	Uid     uint32 `json:"uid,omitempty" column:"uid,template:uid"`
	Gid     uint32 `json:"gid,omitempty" column:"gid,template:gid"`
	Request uint32 `json:"request,omitempty" column:"request,template:request"`
	Comm    string `json:"comm,omitempty" column:"comm,template:comm"`
	ExePath string `json:"exe_path,omitempty" column:"exe_path,template:exe_path"`
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

// GetTimestamp returns the event timestamp
func (event *Event) GetTimestamp() eventtypes.Time {
	return event.Timestamp
}
