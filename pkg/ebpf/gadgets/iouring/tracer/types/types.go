package types

import eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID
	Opcode   uint32 `json:"opcode,omitempty" column:"opcode,template:opcode"`
	Pid      uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Tid      uint32 `json:"tid,omitempty" column:"tid,template:tid"`
	Uid      uint32 `json:"uid,omitempty" column:"uid,template:uid"`
	Gid      uint32 `json:"gid,omitempty" column:"gid,template:gid"`
	Comm     string `json:"comm,omitempty" column:"comm,template:comm"`
	Flags    uint32 `json:"flags,omitempty" column:"flags,template:flags"`
	UserData uint64 `json:"user_data,omitempty" column:"user_data,template:user_data"`
}
