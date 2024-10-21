package events

import (
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

type ExecEvent struct {
	tracerexectype.Event
	extra interface{}
}

func (event *ExecEvent) SetExtra(extra interface{}) {
	event.extra = extra
}

func (event *ExecEvent) GetExtra() interface{} {
	return event.extra
}

func (event *ExecEvent) GetPID() int {
	return int(event.Pid)
}
