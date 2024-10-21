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

func (event *OpenEvent) GetPID() int {
	return int(event.Pid)
}

func (event *OpenEvent) GetExtra() interface{} {
	return event.extra
}
