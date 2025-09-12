package events

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
)

type ExecEvent struct {
	datasource.Data
	extra interface{}
}

func (event *ExecEvent) SetExtra(extra interface{}) {
	event.extra = extra
}

func (event *ExecEvent) GetExtra() interface{} {
	return event.extra
}

func (event *ExecEvent) GetPID() uint64 {
	d, _ := datasource.New(datasource.TypeSingle, "event") // FIXME this won't work
	pidF := d.GetField("proc.pid")
	pid, _ := pidF.Uint32(event.Data)
	return uint64(pid)
}
