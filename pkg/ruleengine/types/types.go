package types

import (
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type SyscallEvent struct {
	eventtypes.Event
	eventtypes.WithMountNsID

	Pid  uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Comm string `json:"comm,omitempty" column:"comm,template:comm"`
	Uid  uint32 `json:"uid" column:"uid,template:uid,hide"`
	Gid  uint32 `json:"gid" column:"gid,template:gid,hide"`

	SyscallName string `json:"syscallName,omitempty" column:"syscallName"`
}
