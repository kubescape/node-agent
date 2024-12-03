package events

import (
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
)

type OpenEvent struct {
	traceropentype.Event
	extra interface{}
}

func (event *OpenEvent) SetExtra(extra interface{}) {
	event.extra = extra
}

func (event *OpenEvent) GetPID() uint64 {
	return (uint64(event.Pid) << 32) | uint64(event.Tid)
}

func (event *OpenEvent) GetExtra() interface{} {
	return event.extra
}
